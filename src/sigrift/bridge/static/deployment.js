/**
 * DeploymentPanel — Deployment status comparison table for edge nodes.
 *
 * Renders a per-node comparison table with color-coded cells to highlight
 * drift across the fleet.  Data comes from GET /api/nodes/deployment.
 */
"use strict";

function DeploymentPanel(dashboard) {
    this.dashboard = dashboard;
    this.data = null;
    this._bindEvents();
}

DeploymentPanel.prototype._bindEvents = function() {
    var self = this;
    var btn = document.getElementById("deploy-refresh-btn");
    if (btn) btn.addEventListener("click", function() { self.refresh(true); });
};

DeploymentPanel.prototype.refresh = function(force) {
    var self = this;
    var btn = document.getElementById("deploy-refresh-btn");
    if (btn) { btn.disabled = true; btn.textContent = "Refreshing..."; }
    var url = "/api/nodes/deployment" + (force ? "?refresh=true" : "");
    this.dashboard.apiFetch(url)
        .then(function(data) {
            self.data = data;
            self._render(data);
        })
        .catch(function(err) {
            var status = document.getElementById("deploy-cache-info");
            if (status) { status.textContent = "Refresh failed; current status is unavailable"; status.style.color = "var(--text-secondary)"; }
            var el = document.getElementById("deploy-table-wrap");
            if (el) el.innerHTML = '<p class="empty-state">Failed to load deployment status: ' + esc(err.message) + '</p>';
        })
        .finally(function() {
            if (btn) { btn.disabled = false; btn.textContent = "Refresh"; }
        });
};

DeploymentPanel.prototype._render = function(data) {
    var wrap = document.getElementById("deploy-table-wrap");
    var empty = document.getElementById("deploy-empty");
    var cacheInfo = document.getElementById("deploy-cache-info");
    if (!wrap) return;

    var nodes = data.nodes || {};
    var nodeIds = Object.keys(nodes).sort();

    if (nodeIds.length === 0) {
        wrap.innerHTML = "";
        if (empty) { empty.style.display = ""; empty.textContent = "No registered nodes. Scanner setup registers nodes automatically; SSH auditing is optional."; }
        if (cacheInfo) { cacheInfo.textContent = "No registered nodes"; cacheInfo.style.color = "var(--text-secondary)"; }
        return;
    }
    if (empty) empty.style.display = "none";

    // A fresh HTTP response says nothing about SSH success or capture health.
    if (cacheInfo) {
        var verified = nodeIds.filter(function(id) { return nodes[id].reachable === true; }).length;
        var unconfigured = nodeIds.filter(function(id) { return nodes[id].ssh_status === "not_configured"; }).length;
        cacheInfo.textContent = "Updated " + fmtTime(data.generated_at || data.cached_at) +
            "; SSH audits: " + verified + " verified, " + unconfigured + " not configured, " +
            (nodeIds.length - verified - unconfigured) + " failed" +
            (data.cached ? " (host audit cached at " + fmtTime(data.cached_at) + ")" : "");
        cacheInfo.style.color = "var(--text-secondary)";
    }

    // Compute fleet consensus for drift detection
    var consensus = this._computeConsensus(nodes, nodeIds);

    // Build table
    var html = '<table class="data-table deploy-compare-table"><thead><tr><th>Property</th>';
    for (var i = 0; i < nodeIds.length; i++) {
        var nid = nodeIds[i];
        var n = nodes[nid];
        // A node heading is not an SSH health verdict. Scope every status to its row.
        html += '<th>' + esc(nid) + (n.hostname ? '<br><small>' + esc(n.hostname) + '</small>' : '') + '</th>';
    }
    html += '</tr></thead><tbody>';

    html += this._sectionHeader("Node reports (no SSH required)", nodeIds.length + 1);
    html += '<tr><td class="deploy-prop-label">Node contact</td>';
    for (var ni = 0; ni < nodeIds.length; ni++) {
        var contact = nodes[nodeIds[ni]];
        var contactLabels = {active: "Recent contact", stale: "Stale contact", offline: "No recent contact", unknown: "No contact reported"};
        html += '<td class="deploy-cell">' + (contactLabels[contact.node_status] || "No contact reported") +
            (contact.last_seen ? '<br><small>' + esc(fmtTime(contact.last_seen)) + '</small>' : '') + '</td>';
    }
    html += '</tr><tr><td class="deploy-prop-label">Scanner reports</td>';
    var protocols = {sdr: "SDR", wifi: "Wi-Fi", bluetooth: "Bluetooth", zigbee: "Zigbee", adsb: "ADS-B"};
    // Fixed causes only; an unknown code from a newer node keeps "error reported".
    var reasons = {starting: "starting capture", sensor_absent: "sensor not connected", sensor_changed: "different sensor connected",
        sensor_unusable: "sensor cannot be opened"};
    for (var li = 0; li < nodeIds.length; li++) {
        var reports = nodes[nodeIds[li]].scanner_status || {};
        var labels = [];
        Object.keys(protocols).forEach(function(protocol) {
            var report = reports[protocol];
            if (!report) return;
            var reason = report.state === "error" && Object.prototype.hasOwnProperty.call(reasons, report.reason) ? reasons[report.reason] : null;
            var label = report.active === true ? "reporting" : reason ? reason : report.state === "error" ? "error reported" :
                report.state === "stopped" ? "stopped" : "report expired";
            labels.push(esc(protocols[protocol] + ": " + label));
        });
        html += '<td class="deploy-cell">' + (labels.join('<br>') || "No scanner report") + '</td>';
    }
    html += '</tr>';

    html += this._sectionHeader("Optional SSH host audit", nodeIds.length + 1);
    html += '<tr><td class="deploy-prop-label">Audit status</td>';
    for (var ri = 0; ri < nodeIds.length; ri++) {
        var rn = nodes[nodeIds[ri]];
        var auditClass = rn.reachable ? "deploy-ok" : rn.ssh_status === "not_configured" ? "" : "deploy-warn";
        var auditLabel = rn.reachable ? "SSH audit verified" : rn.ssh_status === "not_configured" ?
            "SSH audit not configured" : rn.error || "SSH audit failed";
        html += '<td class="deploy-cell ' + auditClass + '">' + esc(auditLabel) +
            (rn.guidance ? '<br><small>' + esc(rn.guidance) + '</small>' : '') + '</td>';
    }
    html += '</tr>';

    // Avoid pages of unknown host fields when normal scanner-only setup has no
    // SSH audit. A host audit never determines whether an RF scanner is active.
    if (nodeIds.some(function(id) { return nodes[id].reachable === true; })) {
    // Getters return plain text; _row escapes each cell exactly once.
    // Section: System Info
    html += this._sectionHeader("System Info", nodeIds.length + 1);
    html += this._row("IP Address", nodeIds, nodes, "ip", null);
    html += this._row("MAC Address", nodeIds, nodes, "mac", null);
    html += this._row("Link Type", nodeIds, nodes, function(n) {
        if (!n.link) return "unknown";
        if (n.link.type === "wifi") return "WiFi (" + (n.link.interface || "") + ")";
        if (n.link.type === "ethernet") return "Ethernet (" + (n.link.interface || "") + ")";
        return n.link.type;
    }, null);
    html += this._row("Link Detail", nodeIds, nodes, function(n) {
        if (!n.link) return "--";
        if (n.link.type === "wifi") {
            var sig = n.link.signal_dbm != null ? n.link.signal_dbm + " dBm" : "";
            return (n.link.ssid || "?") + (sig ? " / " + sig : "");
        }
        if (n.link.type === "ethernet") return (n.link.speed_mbps || "?") + " Mbps";
        return "--";
    }, null);
    html += this._row("OS", nodeIds, nodes, "os", consensus);
    html += this._row("Kernel", nodeIds, nodes, "kernel", consensus);
    html += this._row("Uptime", nodeIds, nodes, function(n) {
        return n.uptime_seconds != null ? fmtUptime(n.uptime_seconds) : "--";
    }, null);

    // Section: Packages
    html += this._sectionHeader("Packages", nodeIds.length + 1);
    html += this._row("Python", nodeIds, nodes, "python", consensus);
    html += this._row("NumPy", nodeIds, nodes, "numpy", consensus);
    html += this._row("ONNX Runtime", nodeIds, nodes, "onnxruntime", consensus);
    html += this._row("Bleak", nodeIds, nodes, "bleak", consensus);
    html += this._row("Bellows", nodeIds, nodes, "bellows", consensus);
    html += this._row("Zigpy", nodeIds, nodes, "zigpy", consensus);
    html += this._row("readsb", nodeIds, nodes, "readsb_version", consensus);

    // Section: Services
    html += this._sectionHeader("Services", nodeIds.length + 1);
    var svcs = ["rf-edge", "mlrf-agent", "mlrf-bt-scanner", "wifi-scan", "readsb", "zigbee-scan"];
    for (var si = 0; si < svcs.length; si++) {
        var svc = svcs[si];
        html += this._serviceRow(svc, nodeIds, nodes);
    }

    // Section: Script Versions
    html += this._sectionHeader("Script Versions", nodeIds.length + 1);
    var scriptNames = [
        {file: "rf_scan.py", label: "rf_scan.py"},
        {file: "node_agent.py", label: "node_agent.py"},
        {file: "bt_scanner.py", label: "bt_scanner.py"},
        {file: "wifi_scan.py", label: "wifi_scan.py"},
        {file: "zigbee_scanner.py", label: "zigbee_scanner.py"}
    ];
    var scriptConsensus = this._computeScriptConsensus(nodes, nodeIds);
    for (var sci = 0; sci < scriptNames.length; sci++) {
        var sf = scriptNames[sci];
        html += this._scriptRow(sf.label, sf.file, nodeIds, nodes, scriptConsensus);
    }
    html += this._oldScriptsRow(nodeIds, nodes);

    // Section: Config Checksums
    html += this._sectionHeader("Config Checksums", nodeIds.length + 1);
    var configFiles = ["rf_scan.py", "node_agent.py", "detection_reporter.py", "edge_inference.py",
                       "zigbee_scanner.py", "rf-edge.service", "mlrf-agent.service", "zigbee-scan.service"];
    var cfgConsensus = this._computeConfigConsensus(nodes, nodeIds);
    for (var ci = 0; ci < configFiles.length; ci++) {
        var cfgName = configFiles[ci];
        html += this._configRow(cfgName, nodeIds, nodes, cfgConsensus);
    }

    // Section: Security
    html += this._sectionHeader("Security", nodeIds.length + 1);
    html += this._row("Firewall", nodeIds, nodes, function(n) {
        if (!n.firewall) return "unknown";
        return n.firewall.active ? "active (" + (n.firewall.policy == null ? "" : n.firewall.policy) + ")" : "INACTIVE";
    }, function(n) {
        return n.firewall && n.firewall.active ? "ok" : "bad";
    });
    html += this._row("Password Auth", nodeIds, nodes, function(n) {
        if (!n.ssh) return "unknown";
        return n.ssh.password_auth ? "YES" : "disabled";
    }, function(n) {
        return n.ssh && !n.ssh.password_auth ? "ok" : "bad";
    });
    html += this._row("Root Login", nodeIds, nodes, function(n) {
        if (!n.ssh) return "unknown";
        return n.ssh.root_login ? "YES" : "disabled";
    }, function(n) {
        return n.ssh && !n.ssh.root_login ? "ok" : "bad";
    });
    html += this._row("API Keys (node)", nodeIds, nodes, function(n) {
        return n.api_keys_unified ? "unified" : "FRAGMENTED";
    }, function(n) {
        return n.api_keys_unified ? "ok" : "bad";
    });
    html += this._row("Keys (fleet)", nodeIds, nodes, function(n) {
        if (n.api_keys_consistent == null) return "--";
        return n.api_keys_consistent ? "shared key" : "unique per node";
    }, null);
    html += this._row("Key (Bridge)", nodeIds, nodes, function(n) {
        if (n.api_key_bridge_valid == null) return "--";
        return n.api_key_bridge_valid ? "valid" : "INVALID";
    }, function(n) {
        if (n.api_key_bridge_valid == null) return "";
        return n.api_key_bridge_valid ? "ok" : "bad";
    });

    // Section: Disk / Memory
    html += this._sectionHeader("Disk / Memory", nodeIds.length + 1);
    html += this._row("Disk Used", nodeIds, nodes, function(n) {
        return n.disk_used_pct != null ? n.disk_used_pct + "%" : "--";
    }, function(n) {
        // Unreported usage is left uncolored, like every other unreported fact.
        if (n.disk_used_pct == null) return "";
        return n.disk_used_pct > 80 ? "bad" : n.disk_used_pct > 60 ? "warn" : "ok";
    });
    html += this._row("Disk Avail", nodeIds, nodes, function(n) {
        return n.disk_avail_gb != null ? n.disk_avail_gb + " GB" : "--";
    }, null);
    html += this._row("RAM", nodeIds, nodes, function(n) {
        if (!n.ram_total_mb) return "--";
        return n.ram_used_mb + " / " + n.ram_total_mb + " MB";
    }, null);

    // Section: ONNX Model
    html += this._sectionHeader("ONNX Model", nodeIds.length + 1);
    html += this._row("ONNX Model", nodeIds, nodes, function(n) {
        return n.model && n.model.filename ? String(n.model.filename) : "none";
    }, consensus);
    html += this._row("Model Size", nodeIds, nodes, function(n) {
        if (!n.model || !n.model.size_bytes) return "--";
        return (n.model.size_bytes / 1048576).toFixed(1) + " MB";
    }, null);
    // Section: Actions
    html += this._sectionHeader("Actions", nodeIds.length + 1);
    html += '<tr><td class="deploy-prop-label">Update</td>';
    for (var ai = 0; ai < nodeIds.length; ai++) {
        var an = nodes[nodeIds[ai]];
        if (an.reachable) {
            html += '<td class="deploy-cell"><button class="btn btn-sm btn-primary deploy-update-btn" data-node="' +
                esc(nodeIds[ai]) + '">Update</button></td>';
        } else {
            html += '<td class="deploy-cell">Unavailable without a verified SSH audit</td>';
        }
    }
    html += '</tr>';
    html += '<tr><td class="deploy-prop-label">Restart</td>';
    for (var ari = 0; ari < nodeIds.length; ari++) {
        var arn = nodes[nodeIds[ari]];
        if (arn.reachable) {
            html += '<td class="deploy-cell"><button class="btn btn-sm deploy-restart-btn" data-node="' +
                esc(nodeIds[ari]) + '">Restart</button></td>';
        } else {
            html += '<td class="deploy-cell">Unavailable without a verified SSH audit</td>';
        }
    }
    html += '</tr>';

    }
    html += '</tbody></table><p class="deploy-guidance">Node contact, scanner reports and SSH host audits are separate checks. Scanner reports expire after 120 seconds. <a href="/static/docs/deployment_guide.html#optional-ssh-audit" target="_blank" rel="noopener">Optional SSH audit setup</a></p>';
    wrap.innerHTML = html;

    // Bind update/restart buttons
    var self2 = this;
    wrap.querySelectorAll('.deploy-update-btn').forEach(function(btn) {
        btn.addEventListener('click', function() { self2._sendCommand(btn.dataset.node, 'update'); });
    });
    wrap.querySelectorAll('.deploy-restart-btn').forEach(function(btn) {
        btn.addEventListener('click', function() { self2._sendCommand(btn.dataset.node, 'restart'); });
    });
};

DeploymentPanel.prototype._sendCommand = function(nodeId, command) {
    var self = this;
    // Matched as text: a node ID is never built into a selector.
    var btns = Array.prototype.filter.call(document.querySelectorAll('.deploy-update-btn, .deploy-restart-btn'), function(b) {
        return b.getAttribute('data-node') === nodeId;
    });
    btns.forEach(function(b) { b.disabled = true; b.textContent = command === 'update' ? 'Updating...' : 'Restarting...'; });

    this.dashboard.apiFetch('/api/nodes/' + encodeURIComponent(nodeId) + '/command', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({command: command, params: {}})
    })
    .then(function(resp) {
        btns.forEach(function(b) { b.textContent = 'Queued'; b.classList.add('btn-success'); });
        setTimeout(function() { self.refresh(false); }, 3000);
    })
    .catch(function(err) {
        // Each button gets back its own label, not the refused command's.
        btns.forEach(function(b) { b.disabled = false; b.textContent = b.classList.contains('deploy-update-btn') ? 'Update' : 'Restart'; });
        alert('Command failed: ' + (err.message || err));
    });
};

DeploymentPanel.prototype._computeConsensus = function(nodes, nodeIds) {
    // For string fields, find the most common value across reachable nodes
    var fields = ["os", "kernel", "python", "numpy", "onnxruntime", "bleak", "bellows", "zigpy", "rf_scan_hash"];
    var cons = {};
    for (var fi = 0; fi < fields.length; fi++) {
        var f = fields[fi];
        var counts = {};
        for (var i = 0; i < nodeIds.length; i++) {
            var n = nodes[nodeIds[i]];
            if (!n.reachable) continue;
            var v = n[f] || "unknown";
            counts[v] = (counts[v] || 0) + 1;
        }
        var best = null, bestCount = 0;
        for (var k in counts) {
            if (counts[k] > bestCount) { best = k; bestCount = counts[k]; }
        }
        cons[f] = best;
    }
    // Model filename consensus
    var modelCounts = {};
    for (var i = 0; i < nodeIds.length; i++) {
        var n = nodes[nodeIds[i]];
        if (!n.reachable || !n.model) continue;
        var mf = n.model.filename || "none";
        modelCounts[mf] = (modelCounts[mf] || 0) + 1;
    }
    var bestModel = null, bestModelCount = 0;
    for (var k in modelCounts) {
        if (modelCounts[k] > bestModelCount) { bestModel = k; bestModelCount = modelCounts[k]; }
    }
    cons["model_filename"] = bestModel;

    return cons;
};

DeploymentPanel.prototype._sectionHeader = function(title, colspan) {
    return '<tr class="deploy-section-header"><td colspan="' + colspan + '"><strong>' + esc(title) + '</strong></td></tr>';
};

DeploymentPanel.prototype._row = function(label, nodeIds, nodes, getter, consensusOrFn) {
    var html = '<tr><td class="deploy-prop-label">' + esc(label) + '</td>';
    for (var i = 0; i < nodeIds.length; i++) {
        var n = nodes[nodeIds[i]];
        if (!n.reachable) {
            html += '<td class="deploy-cell deploy-unreachable">--</td>';
            continue;
        }
        var val, cls;
        if (typeof getter === "function") {
            val = getter(n);
        } else {
            val = n[getter] || "unknown";
        }

        // Determine cell color
        if (typeof consensusOrFn === "function") {
            var status = consensusOrFn(n);
            cls = status === "ok" ? "deploy-ok" : status === "warn" ? "deploy-warn" : status === "bad" ? "deploy-bad" : "";
        } else if (consensusOrFn && typeof getter === "string" && consensusOrFn[getter]) {
            cls = (String(val) === String(consensusOrFn[getter])) ? "deploy-ok" : "deploy-warn";
        } else if (consensusOrFn && typeof getter === "function" && consensusOrFn["model_filename"] && label === "ONNX Model") {
            cls = (val === consensusOrFn["model_filename"]) ? "deploy-ok" : "deploy-warn";
        } else {
            cls = "";
        }

        if (val === "missing" || val === "unknown" || val === "none") cls = "deploy-bad";

        html += '<td class="deploy-cell ' + cls + '">' + esc(val) + '</td>';
    }
    html += '</tr>';
    return html;
};

DeploymentPanel.prototype._computeScriptConsensus = function(nodes, nodeIds) {
    // For each script file, find the most common hash across reachable nodes
    var scripts = ["rf_scan.py", "node_agent.py", "bt_scanner.py", "wifi_scan.py", "zigbee_scanner.py"];
    var cons = {};
    for (var si = 0; si < scripts.length; si++) {
        var sf = scripts[si];
        var counts = {};
        var latest_mtime = 0;
        for (var i = 0; i < nodeIds.length; i++) {
            var n = nodes[nodeIds[i]];
            if (!n.reachable || !n.script_versions) continue;
            var sv = n.script_versions[sf];
            if (!sv || sv.hash === "missing") continue;
            counts[sv.hash] = (counts[sv.hash] || 0) + 1;
            if (sv.mtime > latest_mtime) latest_mtime = sv.mtime;
        }
        // Latest = hash with highest mtime (most recently modified)
        var latestHash = null;
        for (var i2 = 0; i2 < nodeIds.length; i2++) {
            var n2 = nodes[nodeIds[i2]];
            if (!n2.reachable || !n2.script_versions) continue;
            var sv2 = n2.script_versions[sf];
            if (sv2 && sv2.mtime === latest_mtime && sv2.hash !== "missing") {
                latestHash = sv2.hash;
                break;
            }
        }
        cons[sf] = latestHash;
    }
    return cons;
};

DeploymentPanel.prototype._scriptRow = function(label, scriptFile, nodeIds, nodes, scriptConsensus) {
    var html = '<tr><td class="deploy-prop-label">' + esc(label) + '</td>';
    var latestHash = scriptConsensus[scriptFile];
    for (var i = 0; i < nodeIds.length; i++) {
        var n = nodes[nodeIds[i]];
        if (!n.reachable) {
            html += '<td class="deploy-cell deploy-unreachable">--</td>';
            continue;
        }
        var sv = n.script_versions && n.script_versions[scriptFile];
        if (!sv || sv.hash === "missing") {
            html += '<td class="deploy-cell deploy-bad">missing</td>';
            continue;
        }
        var shortHash = sv.hash.substring(0, 8);
        var cls;
        if (latestHash && sv.hash !== latestHash) {
            cls = "deploy-warn";
        } else {
            cls = "deploy-ok";
        }
        html += '<td class="deploy-cell ' + cls + '" title="' + esc(sv.hash) + '">' + esc(shortHash) + '</td>';
    }
    html += '</tr>';
    return html;
};

DeploymentPanel.prototype._oldScriptsRow = function(nodeIds, nodes) {
    // Show a row for any deprecated scripts found on nodes
    var anyOld = false;
    for (var i = 0; i < nodeIds.length; i++) {
        var n = nodes[nodeIds[i]];
        if (n.reachable && n.old_scripts && n.old_scripts.length > 0) { anyOld = true; break; }
    }
    if (!anyOld) return "";

    var html = '<tr><td class="deploy-prop-label">Legacy Scripts</td>';
    for (var i2 = 0; i2 < nodeIds.length; i2++) {
        var n2 = nodes[nodeIds[i2]];
        if (!n2.reachable) {
            html += '<td class="deploy-cell deploy-unreachable">--</td>';
            continue;
        }
        var old = n2.old_scripts || [];
        if (old.length === 0) {
            html += '<td class="deploy-cell deploy-ok">clean</td>';
        } else {
            var names = [];
            for (var j = 0; j < old.length; j++) names.push(old[j].name);
            html += '<td class="deploy-cell deploy-bad" title="' + esc(old.map(function(o){return o.path;}).join(", ")) + '">' + esc(names.join(", ")) + '</td>';
        }
    }
    html += '</tr>';
    return html;
};

DeploymentPanel.prototype._serviceRow = function(svc, nodeIds, nodes) {
    var html = '<tr><td class="deploy-prop-label">' + esc(svc) + '</td>';
    for (var i = 0; i < nodeIds.length; i++) {
        var n = nodes[nodeIds[i]];
        if (!n.reachable) {
            html += '<td class="deploy-cell deploy-unreachable">--</td>';
            continue;
        }
        var svcData = n.services && n.services[svc];
        if (!svcData) {
            html += '<td class="deploy-cell deploy-bad">missing</td>';
            continue;
        }
        var active = svcData.active;
        var enabled = svcData.enabled;
        var label = (active ? "active" : "inactive") + " / " + (enabled ? "enabled" : "disabled");
        var cls = (active && enabled) ? "deploy-ok" : active ? "deploy-warn" : "deploy-bad";
        html += '<td class="deploy-cell ' + cls + '">' + esc(label) + '</td>';
    }
    html += '</tr>';
    return html;
};

DeploymentPanel.prototype._computeConfigConsensus = function(nodes, nodeIds) {
    var cons = {};
    for (var i = 0; i < nodeIds.length; i++) {
        var n = nodes[nodeIds[i]];
        if (!n.reachable || !n.config_checksums) continue;
        for (var file in n.config_checksums) {
            if (!cons[file]) cons[file] = {};
            var h = n.config_checksums[file];
            cons[file][h] = (cons[file][h] || 0) + 1;
        }
    }
    var result = {};
    for (var file in cons) {
        var best = null, bestCount = 0;
        for (var h in cons[file]) {
            if (cons[file][h] > bestCount) { best = h; bestCount = cons[file][h]; }
        }
        result[file] = best;
    }
    return result;
};

DeploymentPanel.prototype._configRow = function(cfgName, nodeIds, nodes, consensus) {
    var html = '<tr><td class="deploy-prop-label">' + esc(cfgName) + '</td>';
    var expected = consensus[cfgName] || null;
    for (var i = 0; i < nodeIds.length; i++) {
        var n = nodes[nodeIds[i]];
        if (!n.reachable) {
            html += '<td class="deploy-cell">Unavailable without a verified SSH audit</td>';
            continue;
        }
        var checksums = n.config_checksums || {};
        var h = checksums[cfgName];
        if (!h) {
            html += '<td class="deploy-cell" style="opacity:0.4">missing</td>';
        } else if (expected && h !== expected) {
            html += '<td class="deploy-cell deploy-bad" title="' + esc(h) + '">DRIFT ' + esc(h.substring(0, 8)) + '</td>';
        } else {
            html += '<td class="deploy-cell deploy-ok" title="' + esc(h) + '">' + esc(h.substring(0, 8)) + '</td>';
        }
    }
    html += '</tr>';
    return html;
};
