/* Alert analysis: most common alert types and RF frequencies, with a reviewed
 * "mark as known" that can also acknowledge the open alerts it covers.
 * All values are inserted with textContent; nothing is parsed as HTML. */
(function () {
    "use strict";
    var BUCKET_LABEL = "100 kHz";
    var state = { db: null, onChange: null, pending: false, seq: 0 };

    function el(tag, text, cls) {
        var node = document.createElement(tag);
        if (text != null) node.textContent = text;
        if (cls) node.className = cls;
        return node;
    }
    function mhz(hz) { return (Math.round(hz / 1e3) / 1e3).toString(); }
    function rangeLabel(min, max) { return min === max ? mhz(min) + " MHz" : mhz(min) + "–" + mhz(max) + " MHz"; }
    function cell(row, text) { row.appendChild(el("td", text)); }
    function set(id, text) { var n = document.getElementById(id); if (n) n.textContent = text; }

    function hoursFromFeed() {
        var sel = document.getElementById("alerts-tab-time");
        var hours = sel && sel.value ? parseInt(sel.value, 10) : 0;
        return hours > 0 ? hours : 24 * 365;
    }

    function renderFrequencies(data) {
        var body = document.getElementById("alert-analysis-freq-body");
        if (!body) return;
        body.replaceChildren();
        (data.frequencies || []).forEach(function (group) {
            var row = el("tr");
            cell(row, rangeLabel(group.freq_min_hz, group.freq_max_hz));
            cell(row, group.node_id);
            cell(row, (group.classes || []).map(function (c) { return c.signal_class + " ×" + c.count; }).join(", "));
            cell(row, (group.alert_types || []).map(function (t) { return t.name; }).join(", "));
            cell(row, group.open + " / " + group.count);
            var actions = el("td");
            if (group.covered_by && group.covered_by.length) {
                actions.appendChild(el("span", "Already known", "alert-analysis-known"));
            } else if (data.can_manage) {
                var btn = el("button", "Mark as known…", "btn btn-sm");
                btn.type = "button";
                btn.setAttribute("data-analysis-known", "");
                btn.addEventListener("click", function () { openDialog(group); });
                actions.appendChild(btn);
            }
            row.appendChild(actions);
            body.appendChild(row);
        });
        var empty = document.getElementById("alert-analysis-freq-empty");
        if (empty) empty.style.display = (data.frequencies || []).length ? "none" : "";
    }

    function renderTypes(data) {
        var body = document.getElementById("alert-analysis-type-body");
        if (!body) return;
        body.replaceChildren();
        (data.alert_types || []).forEach(function (kind) {
            var row = el("tr");
            cell(row, kind.name);
            cell(row, Object.keys(kind.severities || {}).map(function (s) { return s + " ×" + kind.severities[s]; }).join(", "));
            cell(row, (kind.top_frequencies || []).map(function (f) { return rangeLabel(f.freq_min_hz, f.freq_max_hz) + " (" + f.node_id + ") ×" + f.count; }).join("; ") || "—");
            cell(row, kind.open + " / " + kind.count);
            body.appendChild(row);
        });
        var empty = document.getElementById("alert-analysis-type-empty");
        if (empty) empty.style.display = (data.alert_types || []).length ? "none" : "";
    }

    function refresh(db, onChange) {
        if (db) state.db = db;
        if (onChange) state.onChange = onChange;
        if (!state.db) return Promise.resolve();
        var showAcked = document.getElementById("alert-analysis-include-acked");
        var qs = "?hours=" + hoursFromFeed() + "&limit=10" + (showAcked && showAcked.checked ? "&include_acknowledged=true" : "");
        var seq = ++state.seq;
        return state.db.apiFetch("/api/alerts/analysis" + qs).then(function (data) {
            if (seq !== state.seq || !data) return;
            renderFrequencies(data);
            renderTypes(data);
            set("alert-analysis-summary", data.alerts_considered + " alert(s) in window · " +
                (data.frequencies_total || 0) + " frequency group(s) of " + BUCKET_LABEL +
                (data.unlinked_open ? " · " + data.unlinked_open + " open alert(s) have no RF detection to group" : ""));
        }).catch(function () {
            if (seq === state.seq) set("alert-analysis-summary", "Alert analysis unavailable. Refresh to retry.");
        });
    }

    function field(form, label, value, name, type) {
        var wrap = el("label", label);
        var input = el("input");
        input.name = name; input.type = type || "text"; input.className = "form-input";
        if (type === "checkbox") input.checked = Boolean(value); else input.value = value == null ? "" : String(value);
        wrap.appendChild(input); form.appendChild(wrap);
        return input;
    }

    function openDialog(group, db) {
        if (db) state.db = db;
        var s = group.suggested_pattern;
        var dialog = el("dialog", null, "known-signal-dialog");
        dialog.setAttribute("aria-label", "Mark frequency as known");
        dialog.appendChild(el("h2", "Mark frequency as known"));
        dialog.appendChild(el("p", "Future RF alerts matching this range, modulation and node are suppressed. Detections, scores and alert history stay available. This does not verify that a signal is safe.", "known-signal-explanation"));
        var form = el("form", null, "known-signal-form");
        var min = field(form, "Minimum frequency (MHz)", s.freq_min_hz / 1e6, "freq_min_mhz", "number");
        var max = field(form, "Maximum frequency (MHz)", s.freq_max_hz / 1e6, "freq_max_mhz", "number");
        min.step = max.step = "any";
        var any = field(form, "Any modulation (frequency only)", s.signal_class === "*", "any_modulation", "checkbox");
        var cls = field(form, "Signal class", s.signal_class === "*" ? "" : s.signal_class, "signal_class");
        var node = field(form, "Node", s.node_id || "", "node_id");
        var all = field(form, "Apply to all nodes (broader scope)", false, "all_nodes", "checkbox");
        var note = field(form, "Reason (optional)", "", "note"); note.maxLength = 500;
        var ack = field(form, "Acknowledge the " + group.open + " open alert(s) this covers", group.open > 0, "acknowledge_covered", "checkbox");
        function sync() { cls.disabled = any.checked; node.disabled = all.checked; }
        any.addEventListener("change", sync); all.addEventListener("change", sync); sync();
        var save = el("button", "Save known pattern", "btn btn-primary"); save.type = "submit";
        form.appendChild(save);
        var cancel = el("button", "Cancel", "btn btn-sm"); cancel.type = "button";
        cancel.addEventListener("click", function () { dialog.close(); });
        form.appendChild(cancel);
        var status = el("p", "", "known-signal-status");
        status.setAttribute("role", "status"); status.setAttribute("aria-live", "polite");
        dialog.appendChild(form); dialog.appendChild(status);
        dialog.addEventListener("close", function () { dialog.remove(); });
        form.addEventListener("submit", function (event) {
            event.preventDefault();
            if (state.pending) return;
            var low = Number(min.value) * 1e6, high = Number(max.value) * 1e6;
            if (!Number.isFinite(low) || !Number.isFinite(high) || low < 0 || high <= low ||
                (!any.checked && !cls.value.trim()) || (!all.checked && !node.value.trim())) {
                status.textContent = "Enter an increasing frequency range, a signal class or Any modulation, and a node or All nodes.";
                return;
            }
            state.pending = true; save.disabled = true;
            status.textContent = "Saving…";
            state.db.apiFetch("/api/alerts/analysis/known", {
                method: "POST",
                body: {
                    freq_min_hz: low, freq_max_hz: high,
                    signal_class: any.checked ? "*" : cls.value.trim(),
                    node_id: all.checked ? null : node.value.trim(),
                    note: note.value,
                    acknowledge_covered: ack.checked
                }
            }).then(function (result) {
                if (!result || !result.pattern) throw new Error("The save was not confirmed. Refresh before retrying.");
                status.textContent = "Saved. " + result.acknowledged_count + " open alert(s) acknowledged.";
                dialog.close();
                if (typeof showToast === "function") showToast("Known pattern saved; " + result.acknowledged_count + " alert(s) acknowledged", "success");
                refresh();
                if (state.onChange) state.onChange();
            }).catch(function (error) {
                status.textContent = (error && (error.detail || error.message)) || "Could not save. Nothing was confirmed; retry.";
            }).then(function () { state.pending = false; save.disabled = false; });
        });
        document.body.appendChild(dialog);
        dialog.showModal();
        return dialog;
    }

    function init() {
        var btn = document.getElementById("alert-analysis-refresh");
        if (btn) btn.addEventListener("click", function () { refresh(); });
        var acked = document.getElementById("alert-analysis-include-acked");
        if (acked) acked.addEventListener("change", function () { refresh(); });
    }

    window.AlertAnalysis = { refresh: refresh, open: openDialog, init: init };
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init); else init();
})();
