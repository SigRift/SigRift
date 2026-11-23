/**
 * Incident Lifecycle Management — Frontend module.
 *
 * Manages incident CRUD, state transitions, assignment, resolution,
 * timeline display, linked detections, evidence, and SLA metrics.
 */
(function () {
    'use strict';

    var API = '/api/incidents';
    var refreshInterval = null;
    var expandedIncidentId = null;
    var currentFilters = { status: '', severity: '', assigned_to: '' };

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

    // Non-blocking toast/notify shim — defers to window.showToast when
    // dashboard.js has loaded; falls back to console so we never block
    // the event loop or trigger Firefox's "prevent additional dialogs"
    // suppression (ux review P0-7).
    function notify(msg, type) {
        if (typeof window.showToast === 'function') {
            window.showToast(msg, type || 'info');
            return;
        }
        if (type === 'error') console.error(msg);
        else console.log(msg);
    }

    // Briefly highlight a form field that failed inline validation, so
    // the user can see what needs attention without a blocking dialog.
    function flagInvalid(el) {
        if (!el) return;
        var prev = el.style.outline;
        el.style.outline = '2px solid var(--accent-red, #fc8181)';
        el.style.outlineOffset = '1px';
        try { el.focus(); } catch (_) { /* ignore */ }
        var clear = function () {
            el.style.outline = prev || '';
            el.style.outlineOffset = '';
            el.removeEventListener('input', clear);
            el.removeEventListener('change', clear);
        };
        el.addEventListener('input', clear);
        el.addEventListener('change', clear);
        setTimeout(clear, 3000);
    }

    /* HTML-escape text (& < > " ') for element content and for quoted attribute
     * values. Not for unquoted attributes, URLs, inline handlers, script elements or style. */
    function esc(s) {
        if (s == null) return '';
        return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    function fmtTime(iso) {
        if (!iso) return '--';
        try {
            return new Date(iso).toLocaleString(undefined, {
                hour12: false, month: 'short', day: 'numeric',
                hour: '2-digit', minute: '2-digit', second: '2-digit'
            });
        } catch (_) { return esc(iso); }
    }

    function fmtDuration(hours) {
        if (hours == null) return '--';
        if (hours < 1) return Math.round(hours * 60) + 'm';
        if (hours < 24) return hours.toFixed(1) + 'h';
        return (hours / 24).toFixed(1) + 'd';
    }

    function truncId(id) {
        if (!id) return '';
        return id.length > 8 ? id.substring(0, 8) : id;
    }

    // PR-14: prepend a shape glyph via window.severityIcon() so the
    // badge dual-codes severity (Paivio: shape + color). Falls back to
    // text-only if severity.js failed to load. Theme tokens via
    // var(--severity-*) per active theme — see style.css "Severity
    // palette tokens" block.
    function severityBadge(severity) {
        var sev = severity || 'info';
        var icon = (typeof window.severityIcon === 'function') ? window.severityIcon(sev) : '';
        return '<span class="severity-badge ' + esc(sev) + '">' + icon + esc(sev) + '</span>';
    }

    function statusBadge(status) {
        var colors = {
            open: '#fc8181',
            investigating: '#bee3f8',
            escalated: '#d6bcfa',
            resolved: '#c6f6d5',
            closed: '#e2e8f0'
        };
        var bg = colors[status] || '#e2e8f0';
        return '<span style="background:' + bg +
            ';color:#1a1a2e;padding:2px 8px;border-radius:4px;font-size:0.85em;">' +
            esc(status) + '</span>';
    }

    function resolutionBadge(resolution) {
        var colors = {
            confirmed_threat: '#fc8181',
            false_alarm: '#c6f6d5',
            inconclusive: '#fefcbf',
            known_device: '#bee3f8',
            benign: '#c6f6d5'
        };
        var bg = colors[resolution] || '#e2e8f0';
        return '<span style="background:' + bg +
            ';color:#1a1a2e;padding:2px 8px;border-radius:4px;font-size:0.85em;">' +
            esc(resolution ? resolution.replace(/_/g, ' ') : '') + '</span>';
    }

    function eventIcon(eventType) {
        var icons = {
            created: '&#9679;',
            assigned: '&#9758;',
            state_change: '&#8634;',
            note: '&#9998;',
            evidence: '&#128206;',
            detection_linked: '&#128279;',
            escalated: '&#9888;',
            resolved: '&#10004;',
            closed: '&#10006;',
            reopened: '&#8635;'
        };
        return icons[eventType] || '&#8226;';
    }

    // ── Stats Bar ────────────────────────────────────────────────────

    function refreshMetrics() {
        fetch(API + '/metrics', { headers: authHeaders() })
            .then(function (r) { return r.ok ? r.json() : null; })
            .then(function (data) {
                if (!data) return;
                var el;
                el = document.getElementById('inc-stat-total');
                if (el) el.textContent = data.total != null ? data.total : '--';
                el = document.getElementById('inc-stat-open');
                if (el) el.textContent = data.open != null ? data.open : '--';
                el = document.getElementById('inc-stat-investigating');
                if (el) el.textContent = data.investigating != null ? data.investigating : '--';
                el = document.getElementById('inc-stat-escalated');
                if (el) {
                    var escCount = 0;
                    if (data.by_status && data.by_status.escalated != null) {
                        escCount = data.by_status.escalated;
                    }
                    el.textContent = escCount;
                }
                el = document.getElementById('inc-stat-mtta');
                if (el) el.textContent = data.mtta_hours != null ? fmtDuration(data.mtta_hours) : '--';
                el = document.getElementById('inc-stat-mttr');
                if (el) el.textContent = data.mttr_hours != null ? fmtDuration(data.mttr_hours) : '--';

                // Update tab badge with open count
                var openCount = (data.open || 0) + (data.investigating || 0);
                updateTabBadge(openCount);
            })
            .catch(function (e) { console.error('Incident metrics error:', e); });
    }

    function updateTabBadge(count) {
        var badge = document.getElementById('tab-badge-incidents');
        if (!badge) return;
        if (count > 0) {
            badge.textContent = count > 99 ? '99+' : String(count);
            badge.className = 'tab-badge tab-badge-alert badge-visible';
        } else {
            badge.className = 'tab-badge tab-badge-alert';
            badge.textContent = '';
        }
    }

    // ── Incident List ────────────────────────────────────────────────

    // REGRESSION GUARD (ux P0-6, dashboard §10.2):
    //   The 10s auto-refresh tick MUST NOT destroy work-in-progress.
    //   Specifically: typing in inc-note-input-<id>, inc-assign-input-<id>,
    //   inc-resolve-note-<id>, or selecting in inc-resolve-type-<id> must
    //   persist across a refresh tick — as must keyboard focus and the
    //   table's scroll position.
    //
    //   Two-layer defense:
    //     (1) `isOperatorActivelyEditing()` skips the tick entirely when
    //         focus is inside an expanded incident detail panel. This is
    //         the load-bearing defense in open, where the row list itself
    //         is re-rendered via `tbody.innerHTML = html` each refresh.
    //     (2) `renderDetail()` snapshots inline-form input values + focus
    //         + caret selection before clobbering the panel HTML, and
    //         restores them after `wireDetailForms()` rebinds handlers —
    //         covering the case where the tick leaks through (e.g. focus
    //         briefly elsewhere when the tick fires).
    //
    //   If you touch any of these paths, exercise the manual scenario:
    //   scroll to row 30, expand it, type a 60-char note, wait 10s — note,
    //   focus, and scroll position must all be intact.

    // Returns true if document.activeElement lives inside an expanded
    // incident detail panel (text input, textarea, select, button, etc.).
    // Used by the auto-refresh tick to bail out cheaply rather than risk
    // wiping work-in-progress.
    function isOperatorActivelyEditing() {
        var ae = document.activeElement;
        if (!ae || ae === document.body || ae === document.documentElement) return false;
        var n = ae;
        while (n && n !== document.body) {
            if (n.classList) {
                if (n.classList.contains('incident-detail-panel') ||
                    n.classList.contains('detail-row')) {
                    return true;
                }
            }
            if (n.id && (n.id.indexOf('incident-detail-') === 0 ||
                         n.id.indexOf('inc-detail-row-') === 0 ||
                         n.id.indexOf('inc-note-input-') === 0 ||
                         n.id.indexOf('inc-assign-input-') === 0 ||
                         n.id.indexOf('inc-resolve-note-') === 0 ||
                         n.id.indexOf('inc-resolve-type-') === 0)) {
                return true;
            }
            n = n.parentElement;
        }
        return false;
    }

    // Snapshot the user-entered values of the inline forms in the
    // currently-expanded detail panel, so renderDetail() can restore them
    // after replacing panel.innerHTML.
    function snapshotDetailInputs(incidentId) {
        if (!incidentId) return null;
        var ids = [
            'inc-note-input-' + incidentId,
            'inc-assign-input-' + incidentId,
            'inc-resolve-note-' + incidentId,
            'inc-resolve-type-' + incidentId
        ];
        var snap = {};
        var any = false;
        ids.forEach(function (id) {
            var el = document.getElementById(id);
            if (el) {
                snap[id] = { value: el.value, focused: document.activeElement === el };
                // Capture selection range for text inputs so the caret
                // position survives the restore.
                if (el.tagName === 'INPUT' && typeof el.selectionStart === 'number') {
                    try {
                        snap[id].selectionStart = el.selectionStart;
                        snap[id].selectionEnd = el.selectionEnd;
                    } catch (_) { /* some input types reject selection access */ }
                }
                any = true;
            }
        });
        return any ? snap : null;
    }

    function restoreDetailInputs(snap) {
        if (!snap) return;
        Object.keys(snap).forEach(function (id) {
            var el = document.getElementById(id);
            if (!el) return;
            var s = snap[id];
            // Only restore if the user had typed something — otherwise the
            // freshly-rendered default (e.g. current assigned_to value)
            // should win.
            if (s.value !== '' && s.value !== el.value) {
                el.value = s.value;
            }
            if (s.focused) {
                try { el.focus(); } catch (_) {}
                if (typeof s.selectionStart === 'number') {
                    try { el.setSelectionRange(s.selectionStart, s.selectionEnd); } catch (_) {}
                }
            }
        });
    }

    /**
     * Refresh the incident table.
     *
     * @param {{tick?: boolean}} [opts]
     *   - tick: true when invoked by the 10s auto-refresh interval. In
     *     that case we bail out cheaply if the operator is actively
     *     interacting with an inline form (note/assign/resolve) to avoid
     *     destroying their in-progress input. User-initiated calls (filter
     *     change, manual refresh button, post-action callback) leave this
     *     flag unset and always proceed.
     *
     * Scroll position of the table's scroll container is captured before
     * the DOM mutation and restored after, so the operator's position in
     * a long incident list survives a refresh.
     */
    function refreshIncidents(opts) {
        var isTick = !!(opts && opts.tick);
        if (isTick && isOperatorActivelyEditing()) {
            // Operator is mid-edit in an expanded detail panel — skip this
            // tick entirely. The next user action (or the next tick where
            // focus has left the panel) will catch up.
            return;
        }

        var params = [];
        if (currentFilters.status) params.push('status=' + encodeURIComponent(currentFilters.status));
        if (currentFilters.severity) params.push('severity=' + encodeURIComponent(currentFilters.severity));
        if (currentFilters.assigned_to) params.push('assigned_to=' + encodeURIComponent(currentFilters.assigned_to));
        params.push('limit=50');
        var qs = params.length > 0 ? '?' + params.join('&') : '';

        fetch(API + '/' + qs, { headers: authHeaders() })
            .then(function (r) { return r.ok ? r.json() : null; })
            .then(function (data) {
                if (!data) return;
                var tbody = document.getElementById('incidents-tbody');
                var empty = document.getElementById('incidents-empty');
                if (!tbody) return;

                // Capture scroll position of the nearest scroll container
                // (table wrapper) so it can be restored after DOM mutation.
                var scroller = tbody.parentElement;
                while (scroller && scroller !== document.body) {
                    var oy = window.getComputedStyle(scroller).overflowY;
                    if (oy === 'auto' || oy === 'scroll') break;
                    scroller = scroller.parentElement;
                }
                var savedScrollTop = scroller && scroller !== document.body ? scroller.scrollTop : null;

                if (!data.incidents || data.incidents.length === 0) {
                    tbody.innerHTML = '';
                    if (empty) empty.style.display = '';
                    return;
                }
                if (empty) empty.style.display = 'none';

                var html = '';
                data.incidents.forEach(function (inc) {
                    var actions = buildActionButtons(inc);
                    var rowClass = expandedIncidentId === inc.incident_id ? ' class="row-selected"' : '';
                    html += '<tr' + rowClass + ' data-id="' + esc(inc.incident_id) + '" style="cursor:pointer;">' +
                        '<td><code title="' + esc(inc.incident_id) + '">' + esc(truncId(inc.incident_id)) + '</code></td>' +
                        '<td>' + esc(inc.title) + '</td>' +
                        '<td>' + severityBadge(inc.severity) + '</td>' +
                        '<td>' + statusBadge(inc.status) + '</td>' +
                        '<td>' + esc(inc.assigned_to || '--') + '</td>' +
                        '<td>' + fmtTime(inc.created_at) + '</td>' +
                        '<td>' + fmtTime(inc.updated_at) + '</td>' +
                        '<td class="actions-cell">' + actions + '</td>' +
                        '</tr>';

                    // Expanded detail row
                    if (expandedIncidentId === inc.incident_id) {
                        html += '<tr class="detail-row"><td colspan="8">' +
                            '<div id="incident-detail-' + esc(inc.incident_id) + '" class="incident-detail-panel">' +
                            '<div style="text-align:center;padding:16px;color:var(--text-dim);">Loading...</div>' +
                            '</div></td></tr>';
                    }
                });
                tbody.innerHTML = html;

                // Wire click handlers
                var rows = tbody.querySelectorAll('tr[data-id]');
                rows.forEach(function (row) {
                    row.addEventListener('click', function (e) {
                        // Don't toggle on button/input/select clicks
                        if (e.target.closest('button, input, select, textarea, a')) return;
                        var id = row.getAttribute('data-id');
                        toggleDetail(id);
                    });
                });

                // Wire action buttons
                wireActionButtons();

                // Load expanded detail if any. Forward the tick flag so
                // loadDetail() can preserve input values across a
                // tick-driven re-render.
                if (expandedIncidentId) {
                    loadDetail(expandedIncidentId, { tick: isTick });
                }

                // Restore scroll position last — after all DOM mutations
                // have settled — so the operator's view stays put.
                if (savedScrollTop != null && scroller) {
                    scroller.scrollTop = savedScrollTop;
                }
            })
            .catch(function (e) { console.error('Incident list error:', e); });
    }

    function buildActionButtons(inc) {
        var btns = '';
        if (inc.status === 'open') {
            btns += '<button class="btn btn-sm" data-action="investigate" data-id="' +
                esc(inc.incident_id) + '" title="Start investigation">Investigate</button> ';
            btns += '<button class="btn btn-sm" data-action="escalate" data-id="' +
                esc(inc.incident_id) + '" title="Escalate">Escalate</button>';
        } else if (inc.status === 'investigating') {
            btns += '<button class="btn btn-sm" data-action="escalate" data-id="' +
                esc(inc.incident_id) + '" title="Escalate">Escalate</button> ';
            btns += '<button class="btn btn-sm" data-action="resolve" data-id="' +
                esc(inc.incident_id) + '" title="Resolve">Resolve</button>';
        } else if (inc.status === 'escalated') {
            btns += '<button class="btn btn-sm" data-action="resolve" data-id="' +
                esc(inc.incident_id) + '" title="Resolve">Resolve</button>';
        } else if (inc.status === 'resolved') {
            btns += '<button class="btn btn-sm" data-action="close" data-id="' +
                esc(inc.incident_id) + '" title="Close">Close</button>';
        }
        return btns;
    }

    function wireActionButtons() {
        document.querySelectorAll('#incidents-tbody button[data-action]').forEach(function (btn) {
            btn.addEventListener('click', function (e) {
                e.stopPropagation();
                var action = btn.getAttribute('data-action');
                var id = btn.getAttribute('data-id');
                handleAction(action, id);
            });
        });
    }

    function handleAction(action, incidentId) {
        if (action === 'investigate') {
            updateStatus(incidentId, 'investigating');
        } else if (action === 'escalate') {
            updateStatus(incidentId, 'escalated');
        } else if (action === 'resolve') {
            showResolveForm(incidentId);
        } else if (action === 'close') {
            updateStatus(incidentId, 'closed');
        }
    }

    // ── Status Updates ───────────────────────────────────────────────

    function updateStatus(incidentId, newStatus, note) {
        fetch(API + '/' + incidentId + '/status', {
            method: 'PUT',
            headers: getAuthHeaders(),
            body: JSON.stringify({ status: newStatus, note: note || '' })
        })
            .then(function (r) {
                if (!r.ok) throw new Error(r.status + ' ' + r.statusText);
                return r.json();
            })
            .then(function () {
                refreshIncidents();
                refreshMetrics();
                if (expandedIncidentId === incidentId) loadDetail(incidentId);
            })
            .catch(function (e) { console.error('Status update error:', e); notify('Failed to update status: ' + e.message, 'error'); });
    }

    function assignIncident(incidentId, assignedTo) {
        fetch(API + '/' + incidentId + '/assign', {
            method: 'PUT',
            headers: getAuthHeaders(),
            body: JSON.stringify({ assigned_to: assignedTo })
        })
            .then(function (r) {
                if (!r.ok) throw new Error(r.status + ' ' + r.statusText);
                return r.json();
            })
            .then(function () {
                refreshIncidents();
                if (expandedIncidentId === incidentId) loadDetail(incidentId);
            })
            .catch(function (e) { console.error('Assign error:', e); notify('Failed to assign: ' + e.message, 'error'); });
    }

    function resolveIncident(incidentId, resolution, resolutionNote) {
        fetch(API + '/' + incidentId + '/resolve', {
            method: 'PUT',
            headers: getAuthHeaders(),
            body: JSON.stringify({ resolution: resolution, resolution_note: resolutionNote || '' })
        })
            .then(function (r) {
                if (!r.ok) throw new Error(r.status + ' ' + r.statusText);
                return r.json();
            })
            .then(function () {
                refreshIncidents();
                refreshMetrics();
                if (expandedIncidentId === incidentId) loadDetail(incidentId);
            })
            .catch(function (e) { console.error('Resolve error:', e); notify('Failed to resolve: ' + e.message, 'error'); });
    }

    function addNote(incidentId, note) {
        fetch(API + '/' + incidentId + '/notes', {
            method: 'POST',
            headers: getAuthHeaders(),
            body: JSON.stringify({ note: note })
        })
            .then(function (r) {
                if (!r.ok) throw new Error(r.status + ' ' + r.statusText);
                return r.json();
            })
            .then(function () {
                if (expandedIncidentId === incidentId) loadDetail(incidentId);
            })
            .catch(function (e) { console.error('Add note error:', e); notify('Failed to add note: ' + e.message, 'error'); });
    }

    // ── Detail Panel ─────────────────────────────────────────────────

    function toggleDetail(incidentId) {
        if (expandedIncidentId === incidentId) {
            expandedIncidentId = null;
        } else {
            expandedIncidentId = incidentId;
        }
        refreshIncidents();
    }

    /**
     * Fetch and render an incident's detail panel.
     *
     * @param {string} incidentId
     * @param {{tick?: boolean}} [opts]
     *   When tick=true (called from the auto-refresh path) we snapshot the
     *   inline form input values before re-rendering and restore them
     *   after, so the operator's in-progress notes/assignments survive a
     *   refresh cycle.
     */
    function loadDetail(incidentId, opts) {
        var panel = document.getElementById('incident-detail-' + incidentId);
        if (!panel) return;
        var isTick = !!(opts && opts.tick);

        Promise.all([
            fetch(API + '/' + incidentId, { headers: authHeaders() }).then(function (r) { return r.ok ? r.json() : null; }),
            fetch(API + '/' + incidentId + '/timeline', { headers: authHeaders() }).then(function (r) { return r.ok ? r.json() : null; }),
            fetch(API + '/' + incidentId + '/detections', { headers: authHeaders() }).then(function (r) { return r.ok ? r.json() : null; })
        ])
            .then(function (results) {
                var inc = results[0];
                var timeline = results[1];
                var detections = results[2];
                if (!inc) { panel.innerHTML = '<p style="color:var(--accent-red);">Failed to load incident</p>'; return; }
                renderDetail(panel, inc, timeline, detections, { preserveInputs: isTick });
            })
            .catch(function (e) {
                panel.innerHTML = '<p style="color:var(--accent-red);">Error: ' + esc(e.message) + '</p>';
            });
    }

    function renderDetail(panel, inc, timeline, detections, opts) {
        // Snapshot inline-form input state BEFORE clobbering panel.innerHTML
        // so a tick-driven re-render doesn't wipe operator's typing.
        var snap = (opts && opts.preserveInputs) ? snapshotDetailInputs(inc.incident_id) : null;

        var html = '';

        // Description & metadata
        html += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px;">';
        html += '<div>';
        html += '<h4 style="margin:0 0 8px;">Description</h4>';
        html += '<p style="margin:0;color:var(--text-secondary);">' + esc(inc.description || 'No description provided') + '</p>';
        if (inc.node_id) html += '<div style="margin-top:8px;"><strong>Node:</strong> ' + esc(inc.node_id) + '</div>';
        if (inc.freq_hz) html += '<div><strong>Frequency:</strong> ' + (inc.freq_hz / 1e6).toFixed(3) + ' MHz</div>';
        if (inc.signal_class) html += '<div><strong>Signal class:</strong> ' + esc(inc.signal_class) + '</div>';
        if (inc.anomaly_score) html += '<div><strong>Anomaly score:</strong> ' + (inc.anomaly_score * 100).toFixed(0) + '%</div>';
        if (inc.resolution) html += '<div style="margin-top:8px;"><strong>Resolution:</strong> ' + resolutionBadge(inc.resolution) + '</div>';
        if (inc.resolution_note) html += '<div><strong>Resolution note:</strong> ' + esc(inc.resolution_note) + '</div>';
        html += '</div>';

        // Inline forms
        html += '<div>';

        // Assign form
        html += '<div style="margin-bottom:12px;">';
        html += '<label style="font-weight:600;font-size:0.9em;">Assign to</label><br>';
        html += '<div style="display:flex;gap:4px;margin-top:4px;">';
        html += '<input type="text" id="inc-assign-input-' + esc(inc.incident_id) + '" class="form-input" placeholder="Operator name" value="' + esc(inc.assigned_to || '') + '" style="flex:1;">';
        html += '<button class="btn btn-sm btn-primary" id="inc-assign-btn-' + esc(inc.incident_id) + '">Assign</button>';
        html += '</div></div>';

        // Resolve form (show only for non-resolved/closed)
        if (inc.status !== 'resolved' && inc.status !== 'closed') {
            html += '<div style="margin-bottom:12px;">';
            html += '<label style="font-weight:600;font-size:0.9em;">Resolve</label><br>';
            html += '<select id="inc-resolve-type-' + esc(inc.incident_id) + '" class="form-input" style="margin-top:4px;">';
            html += '<option value="">-- Resolution type --</option>';
            html += '<option value="confirmed_threat">Confirmed Threat</option>';
            html += '<option value="false_alarm">False Alarm</option>';
            html += '<option value="inconclusive">Inconclusive</option>';
            html += '<option value="known_device">Known Device</option>';
            html += '<option value="benign">Benign</option>';
            html += '</select>';
            html += '<input type="text" id="inc-resolve-note-' + esc(inc.incident_id) + '" class="form-input" placeholder="Resolution note (optional)" style="margin-top:4px;">';
            html += '<button class="btn btn-sm btn-primary" id="inc-resolve-btn-' + esc(inc.incident_id) + '" style="margin-top:4px;">Resolve</button>';
            html += '</div>';
        }

        // Add note form
        html += '<div>';
        html += '<label style="font-weight:600;font-size:0.9em;">Add Note</label><br>';
        html += '<div style="display:flex;gap:4px;margin-top:4px;">';
        html += '<input type="text" id="inc-note-input-' + esc(inc.incident_id) + '" class="form-input" placeholder="Type a note..." style="flex:1;">';
        html += '<button class="btn btn-sm" id="inc-note-btn-' + esc(inc.incident_id) + '">Add</button>';
        html += '</div></div>';

        html += '</div>';
        html += '</div>';

        // Timeline
        html += '<h4 style="margin:16px 0 8px;">Timeline</h4>';
        if (timeline && timeline.events && timeline.events.length > 0) {
            html += '<div class="incident-timeline">';
            timeline.events.forEach(function (evt) {
                html += '<div class="timeline-event" style="display:flex;gap:8px;padding:4px 0;border-bottom:1px solid var(--border-color);">';
                html += '<span style="min-width:20px;text-align:center;">' + eventIcon(evt.event_type) + '</span>';
                html += '<span style="min-width:140px;color:var(--text-dim);font-size:0.85em;">' + fmtTime(evt.created_at) + '</span>';
                html += '<span style="min-width:80px;font-weight:600;font-size:0.85em;">' + esc(evt.event_type) + '</span>';
                html += '<span style="flex:1;font-size:0.9em;">' + esc(evt.detail) + '</span>';
                if (evt.actor) html += '<span style="color:var(--text-dim);font-size:0.85em;">' + esc(evt.actor) + '</span>';
                html += '</div>';
            });
            html += '</div>';
        } else {
            html += '<p style="color:var(--text-dim);font-size:0.9em;">No timeline events</p>';
        }

        // Linked detections
        html += '<h4 style="margin:16px 0 8px;">Linked Detections</h4>';
        if (detections && detections.detection_ids && detections.detection_ids.length > 0) {
            html += '<div style="display:flex;flex-wrap:wrap;gap:4px;">';
            detections.detection_ids.forEach(function (did) {
                html += '<code style="background:var(--bg-tertiary);padding:2px 6px;border-radius:3px;font-size:0.85em;">' + esc(truncId(did)) + '</code>';
            });
            html += '</div>';
        } else {
            html += '<p style="color:var(--text-dim);font-size:0.9em;">No linked detections</p>';
        }

        // Evidence (parse from timeline events of type "evidence")
        var evidenceEvents = [];
        if (timeline && timeline.events) {
            timeline.events.forEach(function (evt) {
                if (evt.event_type === 'evidence') {
                    try {
                        var parsed = JSON.parse(evt.detail);
                        parsed._time = evt.created_at;
                        parsed._actor = evt.actor;
                        evidenceEvents.push(parsed);
                    } catch (_) {
                        evidenceEvents.push({ evidence_type: 'unknown', reference: evt.detail, description: '', _time: evt.created_at });
                    }
                }
            });
        }
        if (evidenceEvents.length > 0) {
            html += '<h4 style="margin:16px 0 8px;">Evidence</h4>';
            html += '<table class="data-table" style="font-size:0.9em;"><thead><tr>';
            html += '<th>Type</th><th>Reference</th><th>Description</th><th>Added</th>';
            html += '</tr></thead><tbody>';
            evidenceEvents.forEach(function (ev) {
                html += '<tr>';
                html += '<td>' + esc(ev.evidence_type) + '</td>';
                html += '<td><code>' + esc(ev.reference) + '</code></td>';
                html += '<td>' + esc(ev.description) + '</td>';
                html += '<td>' + fmtTime(ev._time) + '</td>';
                html += '</tr>';
            });
            html += '</tbody></table>';
        }

        panel.innerHTML = html;

        // Wire inline form handlers
        wireDetailForms(inc.incident_id);

        // Restore inline-form input values AFTER re-render + re-wire.
        // Only the snapshot from this tick is honored; user-initiated
        // calls (post-action callbacks) pass no snap, so freshly-rendered
        // defaults win.
        restoreDetailInputs(snap);
    }

    function wireDetailForms(incidentId) {
        var assignBtn = document.getElementById('inc-assign-btn-' + incidentId);
        if (assignBtn) {
            assignBtn.addEventListener('click', function () {
                var input = document.getElementById('inc-assign-input-' + incidentId);
                if (input && input.value.trim()) {
                    assignIncident(incidentId, input.value.trim());
                }
            });
        }

        var resolveBtn = document.getElementById('inc-resolve-btn-' + incidentId);
        if (resolveBtn) {
            resolveBtn.addEventListener('click', function () {
                var typeSelect = document.getElementById('inc-resolve-type-' + incidentId);
                var noteInput = document.getElementById('inc-resolve-note-' + incidentId);
                if (typeSelect && typeSelect.value) {
                    resolveIncident(incidentId, typeSelect.value, noteInput ? noteInput.value : '');
                } else {
                    notify('Select a resolution type', 'error');
                    flagInvalid(typeSelect);
                }
            });
        }

        var noteBtn = document.getElementById('inc-note-btn-' + incidentId);
        if (noteBtn) {
            noteBtn.addEventListener('click', function () {
                var input = document.getElementById('inc-note-input-' + incidentId);
                if (input && input.value.trim()) {
                    addNote(incidentId, input.value.trim());
                    input.value = '';
                }
            });
        }
    }

    // ── Resolve Modal (quick action from table) ──────────────────────

    function showResolveForm(incidentId) {
        expandedIncidentId = incidentId;
        refreshIncidents();
        // The detail panel's resolve form will be visible
    }

    // ── Create Incident ──────────────────────────────────────────────

    function createIncident() {
        var form = document.getElementById('incident-create-form');
        if (!form) return;

        var titleInput = document.getElementById('inc-create-title');
        var severitySelect = document.getElementById('inc-create-severity');
        var descInput = document.getElementById('inc-create-desc');
        var nodeInput = document.getElementById('inc-create-node');
        var freqInput = document.getElementById('inc-create-freq');
        var classInput = document.getElementById('inc-create-class');

        var title = titleInput ? titleInput.value.trim() : '';
        if (!title) { notify('Title is required', 'error'); flagInvalid(titleInput); return; }

        var body = {
            title: title,
            severity: severitySelect ? severitySelect.value : 'warning',
            description: descInput ? descInput.value.trim() : '',
            node_id: nodeInput ? nodeInput.value.trim() : '',
            freq_hz: freqInput && freqInput.value ? parseFloat(freqInput.value) : 0.0,
            signal_class: classInput ? classInput.value.trim() : ''
        };

        fetch(API + '/', {
            method: 'POST',
            headers: getAuthHeaders(),
            body: JSON.stringify(body)
        })
            .then(function (r) {
                if (!r.ok) throw new Error(r.status + ' ' + r.statusText);
                return r.json();
            })
            .then(function (inc) {
                // Reset form
                if (titleInput) titleInput.value = '';
                if (descInput) descInput.value = '';
                if (nodeInput) nodeInput.value = '';
                if (freqInput) freqInput.value = '';
                if (classInput) classInput.value = '';
                if (severitySelect) severitySelect.value = 'warning';
                toggleCreateForm(false);
                expandedIncidentId = inc.incident_id;
                refreshIncidents();
                refreshMetrics();
            })
            .catch(function (e) { console.error('Create incident error:', e); notify('Failed to create incident: ' + e.message, 'error'); });
    }

    function toggleCreateForm(show) {
        var form = document.getElementById('incident-create-form');
        if (!form) return;
        if (show === undefined) {
            form.style.display = form.style.display === 'none' ? '' : 'none';
        } else {
            form.style.display = show ? '' : 'none';
        }
    }

    // ── Wire UI ──────────────────────────────────────────────────────

    function init() {
        var tab = document.getElementById('tab-incidents');
        if (!tab) return;

        // Filter controls
        var statusFilter = document.getElementById('inc-filter-status');
        if (statusFilter) statusFilter.addEventListener('change', function () {
            currentFilters.status = statusFilter.value;
            refreshIncidents();
        });

        var sevFilter = document.getElementById('inc-filter-severity');
        if (sevFilter) sevFilter.addEventListener('change', function () {
            currentFilters.severity = sevFilter.value;
            refreshIncidents();
        });

        var assignFilter = document.getElementById('inc-filter-assigned');
        if (assignFilter) {
            var debounce = null;
            assignFilter.addEventListener('input', function () {
                clearTimeout(debounce);
                debounce = setTimeout(function () {
                    currentFilters.assigned_to = assignFilter.value.trim();
                    refreshIncidents();
                }, 400);
            });
        }

        // Create form
        var createBtn = document.getElementById('inc-create-btn');
        if (createBtn) createBtn.addEventListener('click', function () { toggleCreateForm(); });

        var submitBtn = document.getElementById('inc-create-submit');
        if (submitBtn) submitBtn.addEventListener('click', createIncident);

        var cancelBtn = document.getElementById('inc-create-cancel');
        if (cancelBtn) cancelBtn.addEventListener('click', function () { toggleCreateForm(false); });

        // Refresh button
        var refreshBtn = document.getElementById('inc-refresh-btn');
        if (refreshBtn) refreshBtn.addEventListener('click', function () {
            refreshIncidents();
            refreshMetrics();
        });

        // Tab visibility observer
        var observer = new MutationObserver(function () {
            if (tab.classList.contains('active')) {
                refreshIncidents();
                refreshMetrics();
            }
        });
        observer.observe(tab, { attributes: true, attributeFilter: ['class'] });

        // Auto-refresh every 10s when tab is visible. Pass {tick: true}
        // so refreshIncidents() can apply the skip-if-editing guard and
        // preserve in-progress inline-form input values across the tick
        // (regression guard documented above refreshIncidents).
        refreshInterval = setInterval(function () {
            if (tab.classList.contains('active')) {
                refreshIncidents({ tick: true });
                refreshMetrics();
            }
        }, 10000);

        // Expose for dashboard badge updates
        window._incidentRefreshMetrics = refreshMetrics;
    }

    init();
})();
