/**
 * MLRF Gen4 Dashboard - Main JavaScript
 * Manages API communication, WebSocket connections, panel updates,
 * card collapse/expand, theme toggle, and auth flow.
 * Security: All dynamic content is HTML-escaped. No eval(), no innerHTML with untrusted data.
 */
"use strict";

/* -- Utilities -------------------------------------------------- */

/* HTML-escape text (& < > " ') for element content and for quoted attribute
 * values. Not for unquoted attributes, URLs, inline handlers, script elements or style. */
function esc(str) {
    if (str == null) return "";
    return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}
function fmtTime(iso) {
    if (!iso) return "--";
    try { return new Date(iso).toLocaleString(undefined, { hour12:false, month:"short", day:"numeric", hour:"2-digit", minute:"2-digit", second:"2-digit" }); }
    catch(_) { return esc(iso); }
}
function fmtBytes(b) {
    if (b == null) return "--";
    if (b < 1024) return Number(b) + " B";
    return b < 1048576 ? (b/1024).toFixed(1)+" KB" : (b/1048576).toFixed(1)+" MB";
}
function fmtUptime(s) {
    if (s == null || s < 0) return "";
    return Math.floor(s/3600) + "h " + Math.floor((s%3600)/60) + "m";
}
function setText(id, t) { var el = document.getElementById(id); if (el) el.textContent = t; }
function setHTML(id, h) { var el = document.getElementById(id); if (el) el.innerHTML = h; }
/* A failed API call: an Error carrying the HTTP status and the server's
   string detail ("" when the body has none). */
function apiError(status, body) {
    var detail = body && typeof body.detail === "string" ? body.detail : "";
    var err = new Error(detail || "HTTP " + status);
    err.status = status; err.detail = detail;
    return err;
}

/* -- ShinyDashboard Class --------------------------------------- */

function ShinyDashboard() {
    this.apiKey = sessionStorage.getItem("mlrf_api_key") || "";
    this.wsConns = {}; this.wsRetries = {}; this.wsMaxRetries = 5;
    this.pollTimers = {}; this.collapsed = {};
    this.spectrumViewer = null; this.signalBrowser = null;
    this._loadCollapsed(); this._initTheme(); this._initCards();
    this._initExport(); this._initAuth(); this._initModal();
    this._initAlerts(); this._initJobs(); this._initKeys();
    this._startPolling(); this._connectWebSockets(); this._loadActivity();
}

/* -- API Fetch -------------------------------------------------- */

ShinyDashboard.prototype.apiFetch = function(path, opts) {
    var self = this; opts = opts || {};
    var h = opts.headers || {};
    h["Accept"] = "application/json";
    if (opts.body && typeof opts.body === "object" && !(opts.body instanceof FormData)) {
        h["Content-Type"] = "application/json"; opts.body = JSON.stringify(opts.body);
    }
    if (self.apiKey) h["X-API-Key"] = self.apiKey;
    opts.headers = h; opts.credentials = "same-origin";
    return fetch(path, opts).then(function(r) {
        if (r.status === 401) { self._showAuth(); return Promise.reject(new Error("Unauthorized")); }
        if (!r.ok) return r.json().catch(function(){return null;}).then(function(e){return Promise.reject(apiError(r.status, e));});
        if (r.status === 204) return null;
        return (r.headers.get("content-type")||"").indexOf("json") !== -1 ? r.json() : r;
    });
};

/* A write the key's role does not allow (403) is reported, not dropped:
   viewer keys (the default) are read-only; alert, job and evaluation writes
   and the spectrum connection need an analyst key, node commands an admin
   key, key management the master key (which picks the role of a key it
   creates). Other failures stay silent, as before. */
ShinyDashboard.prototype._writeFailed = function(action, err) {
    if (!err || err.status !== 403) return;
    this._showModal("Not permitted",
        "<p>This API key cannot "+esc(action)+": "+esc(err.detail || "permission denied")+".</p>"
        +"<p>Viewer keys are read-only. Ask an administrator for a key with the role this needs.</p>");
};

/* -- WebSocket Manager ------------------------------------------ */

ShinyDashboard.prototype._wsUrl = function(path) {
    var p = location.protocol === "https:" ? "wss:" : "ws:";
    return p + "//" + location.host + path;
};
/* The API key travels as the "bridge-v1, <key>" subprotocol, never in the
   URL: URLs end up in access logs, proxy logs and browser history. */
ShinyDashboard.prototype._wsProtocols = function() {
    return this.apiKey ? ["bridge-v1", this.apiKey] : [];
};
ShinyDashboard.prototype._connectWS = function(name, path, onMsg) {
    var self = this;
    if (!self.apiKey) return;
    if (self.wsConns[name] && self.wsConns[name].readyState <= 1) return;
    if ((self.wsRetries[name]||0) >= self.wsMaxRetries) return;
    var ws; try { ws = new WebSocket(self._wsUrl(path), self._wsProtocols()); } catch(_) { return; }
    self.wsConns[name] = ws;
    ws.onopen = function() { self.wsRetries[name] = 0; self._updateConn(); };
    ws.onmessage = function(ev) { try { onMsg(JSON.parse(ev.data)); } catch(_){} };
    ws.onclose = function() {
        self.wsConns[name] = null; self._updateConn();
        self.wsRetries[name] = (self.wsRetries[name]||0) + 1;
        setTimeout(function() { self._connectWS(name, path, onMsg); }, Math.min(1000 * Math.pow(2, self.wsRetries[name]), 30000));
    };
    ws.onerror = function() { ws.close(); };
};
ShinyDashboard.prototype._connectWebSockets = function() {
    var s = this;
    s._connectWS("status", "/api/nodes/ws/status", function(d){s._onStatusWS(d);});
    s._connectWS("alerts", "/api/alerts/ws/alerts", function(d){s._onAlertWS(d);});
    s._connectWS("training", "/api/training/ws/training", function(d){s._onTrainingWS(d);});
};
ShinyDashboard.prototype._updateConn = function() {
    var el = document.getElementById("connection-status"); if (!el) return;
    var open = false;
    for (var k in this.wsConns) if (this.wsConns[k] && this.wsConns[k].readyState === 1) { open = true; break; }
    el.className = "connection-indicator " + (open ? "connected" : "disconnected");
    el.querySelector(".status-text").textContent = open ? "Connected" : "Disconnected";
};

/* -- Polling ---------------------------------------------------- */

ShinyDashboard.prototype._startPolling = function() {
    var s = this; s._pollStatus(); s._pollNodes(); s._pollTraining();
    s.pollTimers.st = setInterval(function(){s._pollStatus();}, 15000);
    s.pollTimers.nd = setInterval(function(){s._pollNodes();}, 30000);
    s.pollTimers.tr = setInterval(function(){s._pollTraining();}, 10000);
};
ShinyDashboard.prototype._pollStatus = function() {
    this.apiFetch("/api/status").then(function(d) {
        setText("stat-node-count", d.node_count);
        setText("stat-node-detail", d.active_nodes + " active, " + d.stale_nodes + " stale");
        setText("stat-alert-count", d.alert_count);
        setText("stat-job-count", d.running_jobs);
        setText("stat-job-detail", d.pending_jobs + " queued");
        setText("stat-spectrum-status", d.spectrum_connected ? "Active" : "Idle");
        setText("uptime-display", "Uptime: " + fmtUptime(d.uptime_seconds));
    }).catch(function(){});
};

/* -- Node Panel ------------------------------------------------- */

ShinyDashboard.prototype._pollNodes = function() {
    var s = this; s.apiFetch("/api/nodes/").then(function(n){s._renderNodes(n);}).catch(function(){});
};
ShinyDashboard.prototype._renderNodes = function(nodes) {
    var tb = document.getElementById("nodes-tbody"), em = document.getElementById("nodes-empty");
    if (!tb) return;
    setText("node-count-badge", nodes.length);
    if (!nodes.length) { tb.innerHTML = ""; if (em) em.style.display = ""; return; }
    if (em) em.style.display = "none";
    var h = "";
    for (var i = 0; i < nodes.length; i++) {
        var n = nodes[i], st = esc(n.status||"unknown");
        var cap = n.capabilities||{};
        var radio = cap.hardware||cap.device_type||"--";
        var aiHw = cap.gpu||cap.accelerator||"--";
        var mdl = cap.model||"--";
        var platform = cap.platform||cap.board_model||"--";
        var osName = cap.os||"--";
        var updates = cap.pending_updates!=null?cap.pending_updates:"--";
        var updCls = updates!="--"&&updates>0?" has-updates":"";
        var agentVer = cap.agent_version||"";
        var monCls = agentVer ? (st==="active"?"mon-active":st==="stale"?"mon-stale":"mon-offline") : "mon-none";
        var monTxt = agentVer ? "v"+esc(agentVer) : "--";
        var diskPct = cap.disk_percent!=null?cap.disk_percent.toFixed(1)+"%":"--";
        var cpuTemp = cap.cpu_temp!=null?cap.cpu_temp.toFixed(0)+"\u00b0C":"--";
        var loadAvg = cap.load_1m!=null?cap.load_1m.toFixed(2):"--";
        h += "<tr><td><span class=\"node-status "+st+"\"><span class=\"dot\"></span> "+st+"</span></td>"
            +"<td><span class=\"monitor-badge "+monCls+"\"><span class=\"dot\"></span> "+monTxt+"</span></td>"
            +"<td>"+esc(n.node_id)+"</td><td>"+esc(n.host)+"</td>"
            +"<td>"+esc(radio)+"</td><td>"+esc(aiHw)+"</td><td>"+esc(mdl)+"</td>"
            +"<td>"+esc(platform)+"</td><td>"+esc(osName)+"</td>"
            +"<td class=\"updates-cell"+updCls+"\">"+esc(updates)+"</td>"
            +"<td>"+fmtTime(n.last_seen)+"</td>"
            +"<td>"+esc(n.cpu_percent!=null?n.cpu_percent.toFixed(1):"--")+"</td>"
            +"<td>"+esc(n.memory_mb!=null?n.memory_mb.toFixed(0):"--")+"</td>"
            +"<td>"+esc(diskPct)+"</td>"
            +"<td>"+esc(cpuTemp)+"</td>"
            +"<td>"+esc(loadAvg)+"</td>"
            +"<td>"+esc(n.classifications_per_sec!=null?n.classifications_per_sec.toFixed(1):"--")+"</td>"
            +"<td><button class=\"btn btn-sm btn-secondary\" data-cmd-node=\""+esc(n.node_id)+"\">Ping</button></td></tr>";
    }
    tb.innerHTML = h;
    var self = this;
    tb.querySelectorAll("[data-cmd-node]").forEach(function(b) {
        b.addEventListener("click", function() {
            self.apiFetch("/api/nodes/"+encodeURIComponent(this.getAttribute("data-cmd-node"))+"/command",
                {method:"POST", body:{command:"ping",params:{}}}).catch(function(e){self._writeFailed("send node commands", e);});
        });
    });
};
ShinyDashboard.prototype._onStatusWS = function(d) {
    if (d.type==="snapshot" && Array.isArray(d.nodes)) this._renderNodes(d.nodes);
};

/* -- Training Panel --------------------------------------------- */

ShinyDashboard.prototype._pollTraining = function() {
    var s = this;
    s.apiFetch("/api/training/current").then(function(t){s._renderTraining(t);}).catch(function(){});
    s.apiFetch("/api/models").then(function(m){s._renderModels(m);}).catch(function(){});
};
ShinyDashboard.prototype._renderTraining = function(t) {
    setText("training-status-badge", t.running ? "Running" : "Idle");
    setText("train-run-id", t.run_id || "--");
    setText("train-epoch", (t.current_epoch||0) + " / " + (t.total_epochs||"--"));
    setText("train-best-acc", t.best_val_acc ? (t.best_val_acc*100).toFixed(1)+"%" : "--%");
    var pct = t.total_epochs > 0 ? (t.current_epoch/t.total_epochs*100) : 0;
    var bar = document.getElementById("train-progress");
    if (bar) bar.style.width = pct.toFixed(1) + "%";
    if (t.latest_epoch) {
        var e = t.latest_epoch;
        setText("acc-cls", e.acc_cls ? (e.acc_cls*100).toFixed(1)+"%" : "--");
        setText("acc-mt", e.acc_mt ? (e.acc_mt*100).toFixed(1)+"%" : "--");
        setText("acc-fam", e.acc_fam ? (e.acc_fam*100).toFixed(1)+"%" : "--");
        setText("acc-sf", e.acc_sf ? (e.acc_sf*100).toFixed(1)+"%" : "--");
    }
};
ShinyDashboard.prototype._renderModels = function(models) {
    var tb = document.getElementById("models-tbody"); if (!tb) return;
    if (!models||!models.length) { tb.innerHTML="<tr><td colspan=\"4\" class=\"empty-state\">No models</td></tr>"; return; }
    var h = "";
    for (var i = 0; i < models.length; i++) {
        var m = models[i];
        h += "<tr><td>"+esc(m.name)+"</td><td>"+fmtBytes(m.size_bytes)+"</td><td>"+fmtTime(m.modified)+"</td>"
            +"<td><button class=\"btn btn-sm\" data-eval-model=\""+esc(m.model_id)+"\">Evaluate</button></td></tr>";
    }
    tb.innerHTML = h;
    var self = this;
    tb.querySelectorAll("[data-eval-model]").forEach(function(b) {
        b.addEventListener("click", function() {
            var mid = this.getAttribute("data-eval-model");
            self.apiFetch("/api/training/models/"+encodeURIComponent(mid)+"/evaluate",{method:"POST"})
                .then(function(r){self._showModal("Evaluation Queued","Job ID: "+esc(r.job_id));})
                .catch(function(e){self._writeFailed("queue model evaluations", e);});
        });
    });
};
ShinyDashboard.prototype._onTrainingWS = function(d) {
    if (d.current_epoch != null) this._renderTraining(d);
};

/* -- Alert Panel ------------------------------------------------ */

ShinyDashboard.prototype._initAlerts = function() {
    var s = this; s._loadAlerts();
    var fs = document.getElementById("alert-severity-filter");
    var fa = document.getElementById("alert-hide-acked");
    if (fs) fs.addEventListener("change", function(){s._loadAlerts();});
    if (fa) fa.addEventListener("change", function(){s._loadAlerts();});
    var cb = document.getElementById("create-rule-btn");
    if (cb) cb.addEventListener("click", function(){s._createRule();});
};
ShinyDashboard.prototype._loadAlerts = function() {
    var s = this, p = [];
    var sv = document.getElementById("alert-severity-filter");
    if (sv && sv.value) p.push("severity="+sv.value);
    s.apiFetch("/api/alerts/"+(p.length?"?"+p.join("&"):"")).then(function(a){s._renderAlerts(a);}).catch(function(){});
};
ShinyDashboard.prototype._renderAlerts = function(alerts) {
    var c = document.getElementById("alerts-list"), em = document.getElementById("alerts-empty");
    if (!c) return;
    var ha = document.getElementById("alert-hide-acked"), f = alerts;
    if (ha && ha.checked) f = alerts.filter(function(a){return !a.acknowledged;});
    setText("alert-count-badge", f.length);
    if (!f.length) { c.innerHTML=""; if(em)em.style.display=""; return; }
    if (em) em.style.display = "none";
    var h = "";
    for (var i = 0; i < f.length; i++) {
        var a = f[i], sv = esc(a.severity||"warning"), ak = a.acknowledged?" acknowledged":"";
        h += "<div class=\"alert-item "+sv+ak+"\">"
            +"<span class=\"severity-badge "+sv+"\">"+sv+"</span>"
            +"<span class=\"alert-msg\">"+esc(a.message)+"</span>"
            +"<span class=\"alert-time\">"+fmtTime(a.triggered_at)+"</span>";
        if (!a.acknowledged) h += "<button class=\"btn btn-sm\" data-ack-alert=\""+esc(a.alert_id)+"\">Ack</button>";
        h += "</div>";
    }
    c.innerHTML = h;
    var self = this;
    c.querySelectorAll("[data-ack-alert]").forEach(function(b) {
        b.addEventListener("click", function() {
            self.apiFetch("/api/alerts/"+encodeURIComponent(this.getAttribute("data-ack-alert"))+"/ack",{method:"PUT"})
                .then(function(){self._loadAlerts();}).catch(function(e){self._writeFailed("acknowledge alerts", e);});
        });
    });
};
ShinyDashboard.prototype._createRule = function() {
    var n = document.getElementById("rule-name"), sv = document.getElementById("rule-severity");
    if (!n||!n.value.trim()) return; var s = this;
    s.apiFetch("/api/alerts/rules",{method:"POST",body:{name:n.value.trim(),severity:sv?sv.value:"warning",thresholds:{}}})
        .then(function(){n.value="";s._loadAlerts();}).catch(function(e){s._writeFailed("create alert rules", e);});
};
ShinyDashboard.prototype._onAlertWS = function() { this._loadAlerts(); };

/* -- Job Panel -------------------------------------------------- */

ShinyDashboard.prototype._initJobs = function() {
    var s = this; s._loadJobs(); s._loadPresets(); s._loadSchedules();
    var cb = document.getElementById("create-job-btn");
    if (cb) cb.addEventListener("click", function(){s._createJob();});
};
ShinyDashboard.prototype._loadPresets = function() {
    var sel = document.getElementById("job-preset"); if (!sel) return;
    this.apiFetch("/api/jobs/presets").then(function(ps) {
        for (var i=0;i<ps.length;i++) { var o=document.createElement("option"); o.value=ps[i].name; o.textContent=ps[i].name; sel.appendChild(o); }
    }).catch(function(){});
};
ShinyDashboard.prototype._loadJobs = function() {
    var s=this; s.apiFetch("/api/jobs/").then(function(j){s._renderJobs(j);}).catch(function(){});
};
ShinyDashboard.prototype._renderJobs = function(jobs) {
    var tb = document.getElementById("jobs-tbody"); if (!tb) return;
    setText("job-count-badge", jobs.length);
    if (!jobs.length) { tb.innerHTML="<tr><td colspan=\"5\" class=\"empty-state\">No jobs</td></tr>"; return; }
    var h = "";
    for (var i=0;i<jobs.length;i++) {
        var j=jobs[i], st=esc(j.state||"queued");
        h+="<tr><td>"+esc(j.name)+"</td><td><span class=\"job-state "+st+"\">"+st+"</span></td>"
            +"<td>"+esc(j.priority)+"</td><td>"+fmtTime(j.created_at)+"</td>"
            +"<td><button class=\"btn btn-sm\" data-rerun-job=\""+esc(j.job_id)+"\">Rerun</button></td></tr>";
    }
    tb.innerHTML = h; var self = this;
    tb.querySelectorAll("[data-rerun-job]").forEach(function(b) {
        b.addEventListener("click", function() {
            self.apiFetch("/api/jobs/"+encodeURIComponent(this.getAttribute("data-rerun-job"))+"/rerun",{method:"POST"})
                .then(function(){self._loadJobs();}).catch(function(e){self._writeFailed("rerun jobs", e);});
        });
    });
};
ShinyDashboard.prototype._createJob = function() {
    var ne=document.getElementById("job-name"), pe=document.getElementById("job-preset"), pr=document.getElementById("job-priority");
    if (!ne||!ne.value.trim()) return;
    var body = {name:ne.value.trim(), priority:parseInt(pr.value)||0, params:{}};
    if (pe && pe.value) body.preset = pe.value;
    var s=this; s.apiFetch("/api/jobs/",{method:"POST",body:body}).then(function(){ne.value="";s._loadJobs();})
        .catch(function(e){s._writeFailed("create jobs", e);});
};
ShinyDashboard.prototype._loadSchedules = function() {
    var s=this; s.apiFetch("/api/jobs/schedules").then(function(sc) {
        var tb=document.getElementById("schedules-tbody"); if(!tb)return;
        if(!sc.length){tb.innerHTML="<tr><td colspan=\"5\" class=\"empty-state\">No schedules</td></tr>";return;}
        var h="";
        for(var i=0;i<sc.length;i++){var x=sc[i]; h+="<tr><td>"+esc(x.name)+"</td><td>"+esc(x.node_id)+"</td><td>"+esc(x.interval)+"</td><td>"+(x.enabled?"Yes":"No")+"</td><td></td></tr>";}
        tb.innerHTML=h;
    }).catch(function(){});
};

/* -- Key Panel -------------------------------------------------- */

ShinyDashboard.prototype._initKeys = function() {
    var s=this; s._loadKeys();
    var cb=document.getElementById("create-key-btn");
    if(cb) cb.addEventListener("click", function(){s._createKey();});
};
ShinyDashboard.prototype._loadKeys = function() {
    var s=this; s.apiFetch("/api/keys/").then(function(k){s._renderKeys(k);}).catch(function(){});
};
ShinyDashboard.prototype._renderKeys = function(keys) {
    var tb=document.getElementById("keys-tbody"); if(!tb)return;
    if(!keys.length){tb.innerHTML="<tr><td colspan=\"7\" class=\"empty-state\">No keys</td></tr>";return;}
    var h="";
    for(var i=0;i<keys.length;i++){
        var k=keys[i];
        // expires_at is null both for "never expires" and for a stored expiry
        // the server cannot parse (and so rejects); "expired" tells them apart.
        var exp=k.expired?(k.expires_at?"Expired "+fmtTime(k.expires_at):"Expired (invalid date)")
            :(k.expires_at?fmtTime(k.expires_at):"Never");
        h+="<tr><td>"+esc(k.key_id)+"</td><td>"+esc(k.description)+"</td><td>"+fmtTime(k.created_at)+"</td>"
            +"<td>"+exp+"</td><td>"+esc(k.node_id||"--")+"</td><td>"+esc(k.role||"viewer")+"</td><td>"
            +"<button class=\"btn btn-sm\" data-rotate-key=\""+esc(k.key_id)+"\">Rotate</button> "
            // The server refuses to revoke the master key (rotate it instead).
            +(k.key_id==="master"?"":"<button class=\"btn btn-sm btn-danger\" data-revoke-key=\""+esc(k.key_id)+"\">Revoke</button>")
            +"</td></tr>";
    }
    tb.innerHTML=h; var self=this;
    tb.querySelectorAll("[data-rotate-key]").forEach(function(b){
        b.addEventListener("click",function(){
            var kid=this.getAttribute("data-rotate-key");
            self.apiFetch("/api/keys/"+encodeURIComponent(kid)+"/rotate",{method:"PUT"})
                .then(function(r){self._showKeyModal(r.raw_key,r.message);self._loadKeys();})
                .catch(function(e){self._writeFailed("rotate keys", e);});
        });
    });
    tb.querySelectorAll("[data-revoke-key]").forEach(function(b){
        b.addEventListener("click",function(){
            var kid=this.getAttribute("data-revoke-key");
            if(!confirm("Revoke key "+kid+"?"))return;
            self.apiFetch("/api/keys/"+encodeURIComponent(kid),{method:"DELETE"}).then(function(){self._loadKeys();})
                .catch(function(e){self._writeFailed("revoke keys", e);});
        });
    });
};
ShinyDashboard.prototype._createKey = function() {
    var ki=document.getElementById("key-id-input"), de=document.getElementById("key-desc-input"),
        ni=document.getElementById("key-node-input"), ro=document.getElementById("key-role-input");
    if(!ki||!ki.value.trim())return; var s=this;
    var body={key_id:ki.value.trim(),description:de?de.value.trim():""};
    // A node ID makes this a node key bound to that node; without one it is a
    // dashboard key, which the server never lets heartbeat as a node.
    if(ni&&ni.value.trim()) body.node_id=ni.value.trim();
    // The role picked (viewer, the server's default, unless changed): an
    // analyst key is what the alert, job and spectrum writes need.
    if(ro&&ro.value) body.role=ro.value;
    s.apiFetch("/api/keys/",{method:"POST",body:body})
        .then(function(r){s._showKeyModal(r.raw_key,r.message);ki.value="";if(de)de.value="";if(ni)ni.value="";if(ro)ro.value="viewer";s._loadKeys();})
        .catch(function(e){s._writeFailed("create keys", e);});
};
ShinyDashboard.prototype._showKeyModal = function(raw, msg) {
    this._showModal("API Key", "<p>"+esc(msg)+"</p><div class=\"key-display\">"+esc(raw)+"</div>");
};

/* -- Export Panel ------------------------------------------------ */

ShinyDashboard.prototype._initExport = function() {
    var s=this;
    document.querySelectorAll("[data-export]").forEach(function(b){
        b.addEventListener("click",function(){
            var t=this.getAttribute("data-export"), f=this.getAttribute("data-format");
            var u="/api/export/"+encodeURIComponent(t)+"?format="+encodeURIComponent(f);
            /* Fetch with the X-API-Key header (not ?api_key= in the URL)
               and save the response as a file. */
            var h={}; if(s.apiKey) h["X-API-Key"]=s.apiKey;
            fetch(u,{headers:h,credentials:"same-origin"}).then(function(r){
                if(r.status===401){s._showAuth(); throw new Error("Unauthorized");}
                if(!r.ok) throw new Error("HTTP "+r.status);
                return r.blob();
            }).then(function(b){
                var a=document.createElement("a"); a.href=URL.createObjectURL(b);
                a.download=t+"_export."+f; document.body.appendChild(a); a.click();
                setTimeout(function(){URL.revokeObjectURL(a.href); a.remove();},1000);
            }).catch(function(){});
        });
    });
};

/* -- Activity Log ----------------------------------------------- */

ShinyDashboard.prototype._loadActivity = function() {
    var s=this; s.apiFetch("/api/nodes/activity?limit=200").then(function(e){s._renderActivity(e);}).catch(function(){});
};
ShinyDashboard.prototype._renderActivity = function(entries) {
    var c=document.getElementById("activity-log"), em=document.getElementById("activity-empty");
    if(!c)return;
    if(!entries||!entries.length){c.innerHTML="";if(em)em.style.display="";return;}
    if(em)em.style.display="none";
    var h="";
    for(var i=entries.length-1;i>=0;i--){
        var e=entries[i];
        // Warning-level events (e.g. a legacy key claiming a node) stand out.
        var warn=e.details&&e.details.level==="warning"?" activity-warning":"";
        h+="<div class=\"activity-entry"+warn+"\"><span class=\"activity-ts\">"+fmtTime(e.timestamp)+"</span>"
            +"<span class=\"activity-type\">"+esc(e.event_type)+"</span>"
            +"<span class=\"activity-msg\">"+esc(e.message)+"</span></div>";
    }
    c.innerHTML=h; c.scrollTop=c.scrollHeight;
};

/* -- Theme Toggle ----------------------------------------------- */

ShinyDashboard.prototype._initTheme = function() {
    var saved = localStorage.getItem("mlrf_theme") || "dark";
    document.documentElement.setAttribute("data-theme", saved);
    this._themeIcon(saved);
    var s=this, btn=document.getElementById("theme-toggle");
    if(btn) btn.addEventListener("click",function(){
        var cur=document.documentElement.getAttribute("data-theme")||"dark";
        var nxt=cur==="dark"?"light":"dark";
        document.documentElement.setAttribute("data-theme",nxt);
        localStorage.setItem("mlrf_theme",nxt); s._themeIcon(nxt);
    });
};
ShinyDashboard.prototype._themeIcon = function(t) {
    var i=document.querySelector(".theme-icon"); if(i) i.textContent=t==="dark"?"\u263D":"\u2600";
};

/* -- Card Collapse/Expand --------------------------------------- */

ShinyDashboard.prototype._loadCollapsed = function() {
    try { var s=localStorage.getItem("mlrf_collapsed"); this.collapsed=s?JSON.parse(s):{}; } catch(_){ this.collapsed={}; }
};
ShinyDashboard.prototype._saveCollapsed = function() {
    try { localStorage.setItem("mlrf_collapsed",JSON.stringify(this.collapsed)); } catch(_){}
};
ShinyDashboard.prototype._initCards = function() {
    var s=this;
    document.querySelectorAll("[data-collapse]").forEach(function(hdr){
        var key=hdr.getAttribute("data-collapse"), card=hdr.closest(".card");
        if(!card)return;
        if(s.collapsed[key]) card.classList.add("collapsed");
        hdr.addEventListener("click",function(){
            var is=card.classList.toggle("collapsed"); s.collapsed[key]=is; s._saveCollapsed();
        });
    });
};

/* -- Auth Overlay ----------------------------------------------- */

ShinyDashboard.prototype._initAuth = function() {
    var s=this, sub=document.getElementById("auth-submit"), inp=document.getElementById("auth-key-input");
    if(sub) sub.addEventListener("click",function(){s._submitAuth();});
    if(inp) inp.addEventListener("keydown",function(e){if(e.key==="Enter")s._submitAuth();});
};
ShinyDashboard.prototype._showAuth = function() {
    var o=document.getElementById("auth-overlay"); if(o) o.style.display="";
    var i=document.getElementById("auth-key-input"); if(i){i.value="";i.focus();}
};
ShinyDashboard.prototype._submitAuth = function() {
    var i=document.getElementById("auth-key-input"); if(!i||!i.value.trim())return;
    this.apiKey=i.value.trim(); sessionStorage.setItem("mlrf_api_key",this.apiKey);
    var o=document.getElementById("auth-overlay"); if(o) o.style.display="none";
    this._startPolling(); this._connectWebSockets();
};

/* -- Modal ------------------------------------------------------ */

ShinyDashboard.prototype._initModal = function() {
    var s=this;
    document.getElementById("modal-close").addEventListener("click",function(){s._closeModal();});
    document.getElementById("modal-overlay").addEventListener("click",function(e){if(e.target===this)s._closeModal();});
};
ShinyDashboard.prototype._showModal = function(title, body) {
    setText("modal-title",title);
    var b=document.getElementById("modal-body"); if(b) b.innerHTML=body;
    document.getElementById("modal-overlay").style.display="";
};
ShinyDashboard.prototype._closeModal = function() {
    document.getElementById("modal-overlay").style.display="none";
};

/* -- Boot ------------------------------------------------------- */

document.addEventListener("DOMContentLoaded", function() {
    window.dashboard = new ShinyDashboard();
    if (typeof SpectrumViewer === "function") window.dashboard.spectrumViewer = new SpectrumViewer(window.dashboard);
    if (typeof SignalBrowser === "function") window.dashboard.signalBrowser = new SignalBrowser(window.dashboard);
});
