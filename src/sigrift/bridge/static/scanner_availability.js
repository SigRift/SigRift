/* Server-issued scanner leases. Host heartbeats and USB inventory are not leases. */
"use strict";

function ScannerAvailability(onChange) {
    this.nodes = [];
    this._leases = Object.create(null);
    this._reports = Object.create(null);
    this._observedAt = -1;
    this._timer = null;
    this._onChange = onChange;
}

ScannerAvailability.TABS = Object.freeze({
    rf: "sdr", "spectrum-analysis": "sdr", drone: "sdr", iot: "sdr",
    wifi: "wifi", bluetooth: "bluetooth", zigbee: "zigbee", adsb: "adsb"
});
ScannerAvailability.LABELS = Object.freeze({
    sdr: "SDR", wifi: "Wi-Fi", bluetooth: "Bluetooth", zigbee: "Zigbee", adsb: "ADS-B"
});
// Fixed causes a node may give with an "error" report. Anything else (for
// example a code added by a newer node) is shown with the generic wording.
ScannerAvailability.REASONS = Object.freeze(["starting", "sensor_absent", "sensor_changed", "sensor_unusable", "capture_failed"]);
ScannerAvailability.reason = function(report) {
    return report && report.state === "error" && ScannerAvailability.REASONS.indexOf(report.reason) !== -1 ? report.reason : null;
};
// What the operator does about a sensor reason. It depends on the kind:
// Bluetooth is not part of setup, and Zigbee and ADS-B agents select their
// sensor in their own configuration. Null keeps the caller's generic wording.
ScannerAvailability.guidance = function(reason, protocol) {
    if (!Object.prototype.hasOwnProperty.call(ScannerAvailability.LABELS, protocol)) return null;
    var name = ScannerAvailability.LABELS[protocol], bluetooth = protocol === "bluetooth", agent = protocol === "zigbee" || protocol === "adsb";
    if (reason === "sensor_absent") {
        if (bluetooth) return "The Bluetooth adapter is not available. Check that it is present and enabled on this node. Scanning resumes by itself.";
        return "The " + name + " sensor is not connected. Reconnect it to the same USB port and capture resumes by itself. If it is on another port" +
            (protocol === "wifi" ? " or came back under another interface name" : "") + ", " +
            (agent ? "select it again in the " + name + " scanner's own configuration." : "run setup again on this node.");
    }
    if (reason === "sensor_changed") {
        if (bluetooth) return "A different Bluetooth adapter is in place of the selected one. Set MLRF_BT_ADAPTER to the adapter you want and restart the Bluetooth scanner.";
        return "A different " + name + " sensor is connected where the selected one was. " +
            (agent ? "Select it in the " + name + " scanner's own configuration to use it." : "Run setup again on this node to use it.");
    }
    if (reason === "sensor_unusable") {
        return "The " + name + (bluetooth ? " adapter" : " sensor") + " is connected, but the scanner cannot open it. Prepare it on this node again" +
            (protocol === "sdr" ? " with scanner_setup.py prepare-rtl. QUICKSTART explains how to make that last across re-plugs." : ".");
    }
    return null;
};

ScannerAvailability.prototype.update = function(nodes, observedAt) {
    // A delayed HTTP snapshot cannot replace a newer WebSocket observation.
    // Invalid/failed responses leave the previous lease to expire naturally.
    if (!Array.isArray(nodes) || !Number.isFinite(observedAt) || observedAt < this._observedAt) return false;
    var now = performance.now(), next = Object.create(null), self = this;
    nodes.forEach(function(node) {
        if (!node || typeof node.node_id !== "string" || !node.node_id) return;
        var reports = node.scanner_status;
        if (!reports || typeof reports !== "object" || Array.isArray(reports)) return;
        Object.keys(ScannerAvailability.LABELS).forEach(function(protocol) {
            var report = reports[protocol];
            if (!report || report.protocol !== protocol || ["running", "stopped", "error"].indexOf(report.state) === -1) return;
            var seconds = report.expires_in_seconds;
            if (typeof seconds !== "number" || !Number.isFinite(seconds) || seconds < 0 || seconds > 120) return;
            if (typeof report.active !== "boolean" || (report.active && (report.state !== "running" || seconds <= 0))) return;
            if (typeof report.reported_at !== "string" || !Number.isFinite(Date.parse(report.reported_at))) return;
            var key = JSON.stringify([node.node_id, protocol]);
            var timestamp = Date.parse(report.reported_at), previous = self._reports[key];
            // Keep each report's original deadline even after expiry. Replayed
            // snapshots cannot revive an expired lease or undo a newer stop.
            if (previous && timestamp < previous.timestamp) {
                if (self._leases[key] && self._leases[key].deadline > now) next[key] = self._leases[key];
                return;
            }
            var deadline = report.active ? observedAt + seconds * 1000 : 0;
            if (previous && previous.timestamp === timestamp) deadline = Math.min(deadline, previous.deadline);
            // A replay cannot rewrite the state of an existing failure.
            var replay = Boolean(previous) && previous.timestamp === timestamp;
            var state = replay ? previous.state : report.state, reason = ScannerAvailability.reason(report);
            // A replay may drop a reason (the bridge forgets it once the report
            // ages out) but cannot substitute a different one.
            if (replay && reason !== previous.reason) reason = null;
            self._reports[key] = {timestamp: timestamp, deadline: deadline, state: state, reason: reason,
                node: node.node_id, protocol: protocol};
            if (deadline > now) next[key] = { node: node.node_id, protocol: protocol, deadline: deadline };

        });
    });
    this.nodes = nodes;
    this._observedAt = observedAt;
    this._leases = next;
    this._changed();
    return true;
};

ScannerAvailability.prototype.protocolsFor = function(nodeId) {
    var now = performance.now(), protocols = Object.create(null), self = this;
    Object.keys(this._leases).forEach(function(key) {
        var lease = self._leases[key];
        if ((nodeId === undefined || nodeId === lease.node) && lease.deadline > now) protocols[lease.protocol] = true;
    });
    return Object.keys(protocols).sort();
};

ScannerAvailability.prototype.available = function(tab) {
    var protocol = Object.prototype.hasOwnProperty.call(ScannerAvailability.TABS, tab) ? ScannerAvailability.TABS[tab] : null;
    return !protocol || this.protocolsFor().indexOf(protocol) !== -1;
};

ScannerAvailability.prototype.problems = function() {
    var now = performance.now(), reports = this._reports;
    // Only a validated scanner report establishes this history. Generic host
    // inventory cannot create a failure for a never-configured protocol. Keep
    // known failures through missing/failed snapshots until a new healthy lease.
    return Object.keys(reports).sort().map(function(key) { return reports[key]; }).filter(function(report) {
        return report.deadline <= now;
    }).map(function(report) {
        return {node: report.node, protocol: report.protocol, timestamp: report.timestamp,
            state: report.state === 'running' ? 'expired' : report.state, reason: report.reason};
    });
};

ScannerAvailability.prototype._changed = function() {
    if (this._timer !== null) clearTimeout(this._timer);
    this._timer = null;
    var now = performance.now(), deadlines = [], self = this;
    Object.keys(this._leases).forEach(function(key) {
        var lease = self._leases[key];
        if (lease.deadline <= now) delete self._leases[key];
        else deadlines.push(lease.deadline);
    });
    // A valid snapshot may omit a previously seen node. Its tab stays hidden,
    // but the known report must still expire into a warning without another
    // successful fetch (for example when the connection then fails).
    Object.keys(this._reports).forEach(function(key) {
        if (self._reports[key].deadline > now) deadlines.push(self._reports[key].deadline);
    });
    if (deadlines.length) this._timer = setTimeout(function() { self._changed(); }, Math.max(1, Math.min.apply(null, deadlines) - now));
    this._onChange();
};
