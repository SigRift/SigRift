/* Read-only evidence; never start hardware or infer capture from heartbeats. */
(function () {
    'use strict';
    function node(tag, text) {
        var value = document.createElement(tag);
        if (text !== undefined) value.textContent = text;
        return value;
    }
    function SetupChecklist(db) {
        this.db = db;
        this.root = document.getElementById('setup-checklist-rows');
        this.message = document.getElementById('setup-checklist-status');
        this.button = document.getElementById('setup-checklist-refresh');
        this.toggle = document.getElementById('setup-checklist-toggle');
        this.body = document.getElementById('setup-checklist-body');
        this.overview = document.getElementById('setup-checklist-overview');
        this.snapshot = null;
        this.pending = false;
        this.failed = false;
        this.receiptDeadlines = new Map();
        this.receiptTimer = null;
        var self = this;
        this.availability = new ScannerAvailability(function () { self.render(); });
        if (this.button) this.button.addEventListener('click', function () { self.refresh(); });
        if (!db.collapsed || typeof db.collapsed !== 'object' || Array.isArray(db.collapsed)) db.collapsed = {};
        this.expand(db.collapsed['setup-checklist'] !== true, false);
        if (this.toggle) this.toggle.addEventListener('click', function () { self.expand(self.body.hidden, true); });
        var recovery = document.getElementById('scanner-warning-setup');
        if (recovery) recovery.addEventListener('click', function (event) {
            if (event) event.preventDefault();
            self.expand(true, true);
            if (self.toggle) self.toggle.focus();
        });
    }
    SetupChecklist.prototype.expand = function (expanded, remember) {
        if (!this.body || !this.toggle) return;
        this.body.hidden = !expanded;
        this.toggle.setAttribute('aria-expanded', String(expanded));
        this.toggle.textContent = expanded ? 'Hide details' : 'Show details';
        if (remember) {
            this.db.collapsed['setup-checklist'] = !expanded;
            if (typeof this.db._saveCollapsed === 'function') this.db._saveCollapsed();
        }
    };
    SetupChecklist.prototype.refresh = function () {
        if (this.pending || !this.root) return Promise.resolve();
        this.pending = true;
        this.button.disabled = true;
        var self = this, started = performance.now(), controller = new AbortController();
        var deadline = setTimeout(function () { controller.abort(); }, 10000);
        return this.db.apiFetch('/api/nodes/setup-checklist', {signal: controller.signal}).then(function (data) {
            if (!data || ['unreported', 'per_node'].indexOf(data.host_inventory) === -1 || !Array.isArray(data.nodes)
                || typeof data.truncated !== 'boolean' || !Number.isFinite(Date.parse(data.generated_at))
                || data.nodes.some(function (row) { return !row || typeof row.node_id !== 'string'
                    || !row.node_id || !validReceipt(row.setup_readiness) || !row.observations || typeof row.observations !== 'object'
                    || ['rf_record', 'rf_summary', 'wifi_record'].some(function (kind) {
                        var item = row.observations[kind];
                        return !item || ['available', 'empty', 'invalid', 'unavailable'].indexOf(item.status) === -1
                            || (item.status === 'available' ? typeof item.timestamp !== 'string' || !Number.isFinite(Date.parse(item.timestamp)) : item.timestamp !== null);
                    }); })) {
                throw new Error('Invalid setup snapshot');
            }
            self.snapshot = data;
            self.failed = false;
            self.updateReadiness(data.nodes, started);
            self.availability.update(data.nodes, started);
        }).catch(function () {
            self.failed = true;
            self.render();
        }).finally(function () {
            clearTimeout(deadline);
            self.pending = false;
            self.button.disabled = false;
        });
    };
    var readinessReasons = {
        ready: {checked: 'Ready when checked'},
        missing: {not_found: 'No supported adapter found', selected_absent: 'Selected adapter missing'},
        blocked: {driver_in_use: 'Kernel driver owns the receiver', permissions: 'Scanner permissions missing',
            device_unavailable: 'Device node unavailable', management_interface: 'Management / active radio protected',
            monitor_unsupported: 'Monitor mode unsupported', radio_blocked: 'Radio blocked', ambiguous: 'Multiple receivers need an explicit choice'},
        unknown: {unsupported_host: 'Host discovery unavailable', probe_failed: 'Host check incomplete',
            selection_unavailable: 'Saved choice could not be verified', not_checked: 'Not checked (dashboard-only)'}
    };
    function validReceipt(value) {
        if (value == null) return true;
        return typeof value === 'object' && Number.isFinite(Date.parse(value.checked_at))
            && typeof value.fresh === 'boolean' && typeof value.expires_in_seconds === 'number'
            && Number.isFinite(value.expires_in_seconds) && value.expires_in_seconds >= 0 && value.expires_in_seconds <= 300
            && value.fresh === (value.expires_in_seconds > 0)
            && ['sdr', 'wifi'].every(function (kind) {
                var item = value[kind];
                return item && Object.prototype.hasOwnProperty.call(readinessReasons, item.adapter)
                    && Object.prototype.hasOwnProperty.call(readinessReasons[item.adapter], item.reason)
                    && ['selected', 'not_selected', 'unmanaged'].indexOf(item.selection) !== -1;
            });
    }
    SetupChecklist.prototype.updateReadiness = function (rows, started) {
        var self = this, now = performance.now();
        rows.forEach(function (row) {
            var receipt = row.setup_readiness;
            if (!receipt) { self.receiptDeadlines.delete(row.node_id); return; }
            var stamp = Date.parse(receipt.checked_at), previous = self.receiptDeadlines.get(row.node_id);
            var until = started + receipt.expires_in_seconds * 1000;
            // Replaying the same or older host check cannot extend freshness.
            if (previous && stamp <= previous.stamp) until = Math.min(until, previous.until);
            self.receiptDeadlines.set(row.node_id, {stamp: previous ? Math.max(stamp, previous.stamp) : stamp, until: Math.max(now, until)});
        });
    };
    SetupChecklist.prototype.adapter = function (row, protocol) {
        var receipt = row.setup_readiness;
        if (!receipt) return 'Unreported — host check needed';
        var item = receipt[protocol], deadline = this.receiptDeadlines.get(row.node_id);
        var stale = !deadline || performance.now() >= deadline.until;
        var choice = {selected: 'saved choice', not_selected: 'not selected', unmanaged: 'no managed choice'}[item.selection];
        return readinessReasons[item.adapter][item.reason] + ' · ' + choice + ' · checked '
            + new Date(receipt.checked_at).toISOString() + (stale ? ' · stale host check' : ' · recent host check');
    };
    SetupChecklist.prototype.capture = function (row, protocol) {
        if (this.availability.protocolsFor(row.node_id).indexOf(protocol) !== -1) return 'Running — capture verified';
        var report = row.scanner_status && row.scanner_status[protocol];
        if (!report) return 'Not reported';
        var reason = ScannerAvailability.reason(report);
        if (reason === 'starting') return 'Starting capture';
        if (reason === 'sensor_absent') return 'Sensor not connected';
        if (reason === 'sensor_changed') return 'Different sensor connected';
        if (reason === 'sensor_unusable') return 'Sensor cannot be opened';
        if (report.state === 'error') return 'Capture error';
        if (report.state === 'stopped') return 'Stopped';
        return 'Report expired / unconfirmed';
    };
    SetupChecklist.prototype.data = function (row, protocol) {
        var kinds = protocol === 'sdr' ? ['rf_record', 'rf_summary'] : ['wifi_record'];
        var observations = kinds.map(function (kind) { return row.observations[kind]; });
        var valid = [];
        observations.forEach(function (item, index) {
            if (item && item.status === 'available' && Number.isFinite(Date.parse(item.timestamp))) {
                valid.push({stamp: item.timestamp, time: Date.parse(item.timestamp), kind: kinds[index]});
            }
        });
        valid.sort(function (a, b) { return b.time - a.time; });
        var partial = observations.some(function (item) { return !item || ['available', 'empty'].indexOf(item.status) === -1; });
        if (valid.length) return new Date(valid[0].time).toISOString() + (valid[0].kind === 'rf_summary' ? ' (summary hour)' : ' (record time)') + (partial ? ' · other data unavailable' : '');
        return partial ? 'Data check unavailable — retry' : 'No stored observations';
    };
    SetupChecklist.prototype.states = function (row, protocol) {
        var receipt = row.setup_readiness, item = receipt && receipt[protocol];
        var deadline = this.receiptDeadlines.get(row.node_id);
        var stale = receipt && (!deadline || performance.now() >= deadline.until);
        var adapter = {state: 'unreported', label: 'Unknown', tone: 'neutral'};
        if (stale) adapter = {state: 'stale', label: 'Stale check', tone: 'warning'};
        else if (item && item.selection === 'not_selected') adapter = {state: 'not_selected', label: 'Not selected', tone: 'neutral'};
        else if (item) adapter = {state: item.adapter,
            label: {ready: 'Ready when checked', blocked: 'Blocked', missing: 'Missing', unknown: 'Unknown'}[item.adapter],
            tone: {ready: 'success', blocked: 'danger', missing: 'warning', unknown: 'neutral'}[item.adapter]};
        var value = this.capture(row, protocol), capture = {state: 'unreported', label: 'Not reported', tone: 'neutral'};
        if (value === 'Running — capture verified') capture = {state: 'running', label: 'Verified', tone: 'success'};
        else if (value === 'Capture error') capture = {state: 'error', label: 'Error reported', tone: 'danger'};
        else if (value === 'Starting capture') capture = {state: 'starting', label: 'Starting', tone: 'neutral'};
        else if (value === 'Sensor not connected') capture = {state: 'sensor_absent', label: 'Not connected', tone: 'warning'};
        else if (value === 'Different sensor connected') capture = {state: 'sensor_changed', label: 'Different sensor', tone: 'danger'};
        else if (value === 'Sensor cannot be opened') capture = {state: 'sensor_unusable', label: 'Cannot open', tone: 'danger'};
        else if (value === 'Stopped') capture = {state: 'stopped', label: 'Stopped', tone: 'neutral'};
        else if (value === 'Report expired / unconfirmed') capture = {state: 'expired', label: 'Unconfirmed', tone: 'warning'};
        var observations = (protocol === 'sdr' ? ['rf_record', 'rf_summary'] : ['wifi_record']).map(function (kind) { return row.observations[kind]; });
        var unavailable = observations.some(function (entry) { return ['available', 'empty'].indexOf(entry.status) === -1; });
        var recorded = observations.some(function (entry) { return entry.status === 'available'; });
        var data = unavailable ? {state: 'unavailable', label: recorded ? 'Partial check' : 'Check failed', tone: 'warning'}
            : recorded ? {state: 'recorded', label: 'Recorded', tone: 'neutral'} : {state: 'empty', label: 'No data yet', tone: 'neutral'};
        return {adapter: adapter, capture: capture, data: data,
            attention: ['error', 'sensor_absent', 'sensor_changed', 'sensor_unusable', 'expired'].indexOf(capture.state) !== -1 || unavailable
                || (capture.state !== 'running' && item && item.selection === 'selected'
                    && (capture.state === 'stopped' || (!stale && ['blocked', 'missing'].indexOf(item.adapter) !== -1)))};
    };
    function stateCell(state, text) {
        var cell = node('td'), badge = node('span', state.label), detail = node('p', text);
        cell.setAttribute('data-check-state', state.state);
        badge.setAttribute('class', 'setup-check-state setup-check-' + state.tone);
        detail.setAttribute('class', 'setup-check-detail');
        cell.appendChild(badge); cell.appendChild(detail); return cell;
    }
    SetupChecklist.prototype.remedy = function (row, protocol) {
        var state = this.capture(row, protocol);
        if (state === 'Running — capture verified' && this.states(row, protocol).data.state === 'unavailable') return 'Capture is reporting healthy, but the stored-data check failed. Retry status; this does not restart capture or change configuration.';
        if (state === 'Running — capture verified') return 'Capture is reporting healthy. Quiet air, filters or summary mode can mean no new individual records; data is a separate check.';
        // The live capture report is newer evidence than the last host check.
        if (state === 'Starting capture') return 'The scanner has started and is not capturing yet. No action is needed.';
        // Same advice as the dashboard warning, so the two never disagree.
        var advice = ScannerAvailability.guidance(ScannerAvailability.reason(row.scanner_status && row.scanner_status[protocol]), protocol);
        if (advice) return advice;
        var receipt = row.setup_readiness, item = receipt && receipt[protocol];
        if (item && item.reason === 'selected_absent') return 'Reconnect the saved adapter, then retry the ordinary quickstart command on this host. The saved choice is preserved; do not substitute a management interface.';
        if (item && item.reason === 'permissions') return 'Review the selected device permissions with the host setup planner, then retry. This page cannot change permissions.';
        if (item && item.reason === 'management_interface') return 'Use a separate monitor-capable radio. Keep the management connection intact; never disconnect wlan0 to satisfy this check.';
        var service = protocol === 'sdr' ? 'scan / rtl-tcp' : 'wifi-scan';
        if (state === 'Capture error') return 'Inspect ' + service + ' logs on this scanner host. Check its adapter, permissions/model or capture interface; preserve the management network.';
        if (state === 'Report expired / unconfirmed') return 'Check the scanner process, gateway reachability, CA trust and node-bound key. Refresh status after restoring connectivity; a missing report does not prove missing hardware.';
        return 'On the scanner host, review discovery and saved selection. Rerun the existing quickstart command without changing flags; choose hardware explicitly only when no selection exists.';
    };
    SetupChecklist.prototype.render = function () {
        if (!this.root) return;
        clearTimeout(this.receiptTimer);
        this.root.replaceChildren();
        var self = this;
        if (!this.snapshot) {
            if (this.overview) {
                this.overview.textContent = this.failed ? 'Status unavailable — retry' : 'Checking status…';
                this.overview.setAttribute('data-needs-attention', String(this.failed));
            }
            this.message.textContent = this.failed ? 'Setup checks unavailable. Retry status; no configuration has changed.' : 'Loading setup checks…';
            return;
        }
        this.message.textContent = this.failed
            ? 'Refresh failed. Showing the last successful snapshot; capture leases still expire. Retry status changes no configuration.'
            : 'Adapter readiness is an authenticated last host check, not continuous inventory. Capture and stored data are independent checks.';
        if (this.snapshot.truncated) this.message.textContent += ' Showing the first 100 registered nodes; this is not a complete inventory.';
        if (!this.snapshot.nodes.length) {
            if (this.overview) {
                this.overview.textContent = 'No registered nodes' + (this.failed ? ' · refresh failed' : '');
                this.overview.setAttribute('data-needs-attention', String(this.failed));
            }
            var empty = node('tr'), cell = node('td', 'No nodes registered. Adapter readiness is unreported, not “no adapter”. Review scanner-host setup; do not change the management interface.');
            cell.colSpan = 5; empty.appendChild(cell); this.root.appendChild(empty); return;
        }
        var running = 0, attention = 0, unreported = 0;
        this.snapshot.nodes.forEach(function (row) {
            ['sdr', 'wifi'].forEach(function (protocol) {
                var tr = node('tr');
                tr.setAttribute('data-setup-node', row.node_id);
                tr.setAttribute('data-setup-protocol', protocol);
                var states = self.states(row, protocol);
                if (states.capture.state === 'running') running += 1; else unreported += 1;
                if (states.attention) attention += 1;
                tr.appendChild(node('td', row.node_id + ' · ' + (protocol === 'sdr' ? 'SDR' : 'Wi-Fi')));
                tr.appendChild(stateCell(states.adapter, self.adapter(row, protocol)));
                tr.appendChild(stateCell(states.capture, self.capture(row, protocol)));
                tr.appendChild(stateCell(states.data, self.data(row, protocol)));
                tr.appendChild(node('td', self.remedy(row, protocol)));
                self.root.appendChild(tr);
            });
        });
        if (this.overview) {
            this.overview.textContent = running + (running === 1 ? ' capture running' : ' captures running')
                + (attention ? ' · ' + attention + (attention === 1 ? ' scanner needs attention' : ' scanners need attention') : '')
                + (unreported ? ' · ' + unreported + ' without capture reports' : '')
                + (this.failed ? ' · refresh failed' : '') + (this.snapshot.truncated ? ' · partial inventory' : '');
            this.overview.setAttribute('data-needs-attention', String(attention > 0 || this.failed));
        }
        var future = this.snapshot.nodes.map(function (row) { return self.receiptDeadlines.get(row.node_id); })
            .filter(function (item) { return item && item.until > performance.now(); });
        if (future.length) this.receiptTimer = setTimeout(function () { self.render(); }, Math.min.apply(null, future.map(function (item) { return item.until - performance.now(); })));
    };
    window.SetupChecklist = SetupChecklist;
}());
