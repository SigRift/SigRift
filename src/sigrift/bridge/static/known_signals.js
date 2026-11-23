/* Reviewed operator patterns suppress matching RF alerts; never alter detections. */
(function () {
    "use strict";
    var active = null;
    function element(tag, text, cls) {
        var node = document.createElement(tag);
        if (text != null) node.textContent = text;
        if (cls) node.className = cls;
        return node;
    }
    function button(text, action) {
        var node = element("button", text, "btn btn-sm");
        node.type = "button";
        node.addEventListener("click", action);
        return node;
    }
    function openDialog(title) {
        if (active) { active.close(); active.remove(); }
        var dialog = element("dialog", null, "known-signal-dialog");
        dialog.setAttribute("aria-label", title);
        dialog.appendChild(element("h2", title));
        dialog.appendChild(element("p", "Suppress future RF alerts matching the monitored frequency range, modulation choice and node below. Power changes do not affect matching. Detections, scores and existing alerts stay available. This does not verify that a signal is safe. Scanner frequency is the receiver’s tuned center, not a measured transmitter frequency.", "known-signal-explanation"));
        dialog.appendChild(element("p", "Saved in the detection database and its backups. Config-only and legacy baseline exports do not include these patterns.", "known-signal-explanation"));
        var content = element("div");
        dialog.appendChild(content);
        var status = element("p", "Loading…", "known-signal-status");
        status.setAttribute("role", "status");
        status.setAttribute("aria-live", "polite");
        dialog.appendChild(status);
        dialog.appendChild(button("Close", function () { dialog.close(); }));
        document.body.appendChild(dialog);
        dialog.addEventListener("close", function () {
            if (active === dialog) active = null;
            dialog.remove();
        });
        active = dialog;
        dialog.showModal();
        return { dialog: dialog, content: content, status: status };
    }
    function message(view, text) { view.status.textContent = text; }
    function fail(view, error) {
        message(view, (error && (error.detail || error.message)) || "Could not confirm the change. Refresh or retry; no success has been confirmed.");
    }
    function input(form, label, value, name, type) {
        var wrap = element("label", label);
        var node = element("input");
        node.name = name; node.type = type || "text"; node.value = value == null ? "" : String(value);
        node.className = "form-input";
        wrap.appendChild(node); form.appendChild(wrap);
        return node;
    }
    function description(pattern) {
        return (pattern.freq_min_hz / 1e6) + "–" + (pattern.freq_max_hz / 1e6) + " MHz · " + (pattern.signal_class === "*" ? "Any modulation (frequency only)" : pattern.signal_class) + " · " + (pattern.node_id || "All nodes");
    }
    function remove(db, view, pattern, done) {
        return db.apiFetch("/api/detections/known-signals/" + encodeURIComponent(pattern.pattern_id) + "?revision=" + pattern.revision, { method: "DELETE" }).then(function (data) {
            if (!data || data.removed !== true) throw new Error("Removal was not confirmed. Refresh the list before retrying.");
            message(view, "Known pattern removed. Matching RF alerts are enabled again; normal alert thresholds and cooldowns still apply.");
            done();
        });
    }
    function form(db, view, values, target, canManage, preset) {
        var creating = !target && !values.pattern_id;
        view.content.replaceChildren();
        var editor = element("form", null, "known-signal-form");
        var min = input(editor, "Minimum frequency (MHz)", values.freq_min_hz == null ? "" : values.freq_min_hz / 1e6, "freq_min_mhz", "number");
        var max = input(editor, "Maximum frequency (MHz)", values.freq_max_hz == null ? "" : values.freq_max_hz / 1e6, "freq_max_mhz", "number");
        min.step = max.step = "any"; min.min = "0"; max.min = "0.000001";
        min.required = max.required = true;
        var any = input(editor, "Any modulation (frequency only)", "", "any_modulation", "checkbox");
        any.checked = Boolean(target) || values.signal_class === "*";
        var cls = input(editor, target ? "Source signal class" : "Specific signal class", values.signal_class === "*" ? "" : values.signal_class, "signal_class");
        cls.maxLength = 128; cls.readOnly = Boolean(target);
        cls.pattern = "[a-zA-Z0-9_\\/.\\-]{1,128}";
        function modulationChanged() { cls.disabled = any.checked || !canManage; cls.required = !any.checked; }
        any.addEventListener("change", modulationChanged);
        var node = input(editor, "Node", values.node_id || "", "node_id");
        node.maxLength = 128;
        if (creating) {
            var choices = element("datalist"); choices.id = "known-signal-node-options";
            node.setAttribute("list", choices.id); editor.appendChild(choices);
            var nodeHelp = element("p", "Loading registered node suggestions…", "known-signal-explanation");
            editor.appendChild(nodeHelp);
            db.apiFetch("/api/nodes/").then(function (nodes) {
                if (!Array.isArray(nodes)) throw new Error("Invalid node list");
                var seen = new Set();
                nodes.forEach(function (item) {
                    var id = item && item.node_id;
                    if (typeof id !== "string" || !id.trim() || id.length > 128 || seen.has(id)) return;
                    seen.add(id);
                    var option = element("option", id); option.value = id; choices.appendChild(option);
                });
                nodeHelp.textContent = seen.size ? "Choose a registered node suggestion or enter a known node ID. Registration alone does not confirm capture." : "No registered nodes reported. Enter a known node ID, or explicitly choose all nodes.";
            }).catch(function () {
                nodeHelp.textContent = "Node suggestions unavailable. Enter a known node ID, or explicitly choose all nodes.";
            });
        }
        var all = input(editor, "Apply to all nodes (broader scope)", "", "all_nodes", "checkbox");
        all.checked = values.node_id === null;
        function scopeChanged() { node.disabled = all.checked || !canManage; node.required = !all.checked; }
        all.addEventListener("change", scopeChanged);
        var note = input(editor, "Reason (optional)", values.note || "", "note"); note.maxLength = 500;
        Array.from(editor.querySelectorAll("input")).forEach(function (field) { field.disabled = !canManage; });
        scopeChanged();
        modulationChanged();
        var save = element("button", target ? "Save known pattern" : (creating ? "Save alert rule" : "Save changes"), "btn btn-primary"); save.type = "submit";
        save.disabled = !canManage;
        editor.appendChild(save);
        editor.appendChild(button("Manage known patterns", function () { list(db); }));
        view.content.appendChild(editor);
        message(view, canManage ? (target ? "Review the scope before saving. The initial range is ±50 kHz around the source detection." : "The saved scope is shown. Review your changes before saving.") : "Read-only. An analyst or administrator can change known patterns.");
        if (creating && canManage) message(view, preset ? "Review the " + preset + " starting bounds for your region and setup, then choose a node or explicitly apply to all nodes. Bounds are editable; nothing is enabled until you save." : "Enter the frequency range and a node, or explicitly choose all nodes. Nothing is enabled until you save.");
        var pending = false;
        editor.addEventListener("submit", function (event) {
            event.preventDefault();
            if (pending || !canManage) return;
            var low = Number(min.value) * 1e6, high = Number(max.value) * 1e6;
            if (!min.value || !max.value || !Number.isFinite(low) || !Number.isFinite(high) || low < 0 || high <= low || (!all.checked && !node.value.trim())) {
                message(view, "Enter a valid increasing frequency range and a node, or explicitly choose all nodes."); return;
            }
            if (!any.checked && (!cls.value || cls.value.length > 128 || /[^a-zA-Z0-9_/.-]/.test(cls.value))) {
                message(view, "Enter a valid signal class, or choose Any modulation (frequency only)."); return;
            }
            var body = { freq_min_hz: low, freq_max_hz: high, signal_class: any.checked ? "*" : cls.value, node_id: all.checked ? null : node.value.trim(), note: note.value };
            var url = "/api/detections/known-signals/" + encodeURIComponent(values.pattern_id || "");
            if (target) url = "/api/detections/anomalies/" + encodeURIComponent(target) + "/baseline";
            else if (!creating) body.revision = values.revision;
            if (creating) url = "/api/detections/known-signals";
            pending = true; save.disabled = true; message(view, "Saving…");
            db.apiFetch(url, { method: creating ? "POST" : "PUT", body: body }).then(function (data) {
                var saved = target ? data && data.pattern : data;
                if (!saved || !saved.pattern_id || !Number.isInteger(saved.revision) || (target && data.baselined !== true)) throw new Error("Save was not confirmed. Refresh the list before retrying.");
                view.content.replaceChildren(element("p", description(saved)), element("p", saved.note || ""));
                view.content.appendChild(button(creating ? "Remove this pattern" : "Undo / remove this pattern", function () {
                    if (pending) return;
                    pending = true;
                    remove(db, view, saved, function () { view.content.replaceChildren(); }).catch(function (error) { fail(view, error); }).finally(function () { pending = false; });
                }));
                view.content.appendChild(button("Manage known patterns", function () { list(db); }));
                message(view, "Known pattern saved. Future matching RF alerts are suppressed; all detections and existing alerts are preserved.");
            }).catch(function (error) { fail(view, error); }).finally(function () { pending = false; save.disabled = !canManage; });
        });
    }
    function open(db, detectionId) {
        var view = openDialog("Mark RF signal as known");
        db.apiFetch("/api/detections/anomalies/" + encodeURIComponent(detectionId) + "/baseline").then(function (data) {
            if (!data || data.detection_id !== detectionId || !data.defaults) throw new Error("RF detection could not be verified.");
            form(db, view, data.defaults, detectionId, data.can_manage === true);
            if (data.matching_patterns && data.matching_patterns.length) message(view, "This detection already matches a known pattern. Manage patterns to review or remove it; saving the same scope will not create a duplicate.");
        }).catch(function (error) { fail(view, error); });
    }
    function namedBands(db) {
        // Reuse the condition-rule dashboard catalog; never guess a fallback
        // range if that shared mapping is missing or malformed.
        var source = db._CB_FREQ_BANDS, seen = new Set();
        if (!Array.isArray(source) || !source.length || source.length > 32) return [];
        var valid = source.every(function (band) {
            if (!band || typeof band.label !== "string" || !band.label.trim() || band.label.length > 80
                || seen.has(band.label) || typeof band.min !== "number" || typeof band.max !== "number"
                || !Number.isFinite(band.min) || !Number.isFinite(band.max)
                || band.min < 0 || band.max <= band.min || band.max > Number.MAX_SAFE_INTEGER) return false;
            seen.add(band.label); return true;
        });
        return valid ? source.map(function (band) { return {label: band.label, min: band.min, max: band.max}; }) : [];
    }
    function list(db, settings) {
        var view = openDialog(settings ? "Alert settings" : "Known RF patterns");
        db.apiFetch("/api/detections/known-signals").then(function (data) {
            if (!data || !Array.isArray(data.patterns)) throw new Error("Known patterns could not be loaded.");
            view.content.replaceChildren();
            view.content.appendChild(element("p", "Only the ranges you save are suppressed. These rules suppress RF alerts only; even a WiFi-named band does not affect separate Wi-Fi or Bluetooth protocol alerts and does not stop capture. Other alerts still follow their rules, thresholds and cooldowns. This does not automatically alert only on new frequencies.", "known-signal-explanation"));
            if (data.can_manage === true) {
                var bands = namedBands(db);
                function reviewBand(band) {
                    form(db, view, {freq_min_hz: band.min, freq_max_hz: band.max, signal_class: "*", node_id: "", note: band.label === "FM Broadcast" ? "FM broadcast range" : band.label + " range"}, null, true, band.label);
                }
                var fm = bands.find(function (band) { return band.label === "FM Broadcast"; });
                if (fm) view.content.appendChild(button("Ignore FM broadcast range…", function () { reviewBand(fm); }));
                if (bands.length) {
                    var label = element("label", "Named RF band"); label.setAttribute("for", "known-signal-named-band");
                    var picker = element("select"); picker.setAttribute("id", "known-signal-named-band"); picker.name = "named_rf_band"; picker.className = "form-input";
                    var placeholder = element("option", "Choose a band to review…"); placeholder.value = ""; picker.appendChild(placeholder);
                    bands.forEach(function (band, index) {
                        var option = element("option", band.label + " · " + (band.min / 1e6) + "–" + (band.max / 1e6) + " MHz");
                        option.value = String(index); picker.appendChild(option);
                    });
                    view.content.appendChild(label); view.content.appendChild(picker);
                    function selectedBand() { return /^(0|[1-9][0-9]*)$/.test(picker.value) ? bands[Number(picker.value)] : null; }
                    var review = button("Review selected band", function () { var band = selectedBand(); if (band) reviewBand(band); });
                    review.disabled = true;
                    picker.addEventListener("change", function () { review.disabled = !selectedBand(); });
                    view.content.appendChild(review);
                } else view.content.appendChild(element("p", "Named bands unavailable. Enter a custom frequency range instead."));
                view.content.appendChild(button("Add custom frequency range", function () {
                    form(db, view, {freq_min_hz: null, freq_max_hz: null, signal_class: "*", node_id: "", note: ""}, null, true, null);
                }));
            }
            data.patterns.forEach(function (pattern) {
                var row = element("section", null, "known-signal-entry");
                row.appendChild(element("p", description(pattern)));
                row.appendChild(element("p", pattern.note || ""));
                if (data.can_manage === true) {
                    row.appendChild(button("Edit", function () { form(db, view, pattern, null, true); }));
                    var pending = false;
                    var removeButton = button("Remove", function () {
                        if (pending || !window.confirm("Remove this known pattern? Matching RF alerts will be enabled again. Detection history is unchanged.")) return;
                        pending = true; removeButton.disabled = true;
                        remove(db, view, pattern, function () { row.remove(); }).catch(function (error) { fail(view, error); }).finally(function () { pending = false; removeButton.disabled = false; });
                    });
                    row.appendChild(removeButton);
                }
                view.content.appendChild(row);
            });
            message(view, data.patterns.length ? (data.can_manage ? "Changes apply to future matching RF alerts." : "Read-only. An analyst or administrator can change these patterns.") : "No operator-known RF patterns saved.");
        }).catch(function (error) { fail(view, error); });
    }
    function bind(container, db) {
        container.querySelectorAll("[data-known-detection]").forEach(function (node) {
            node.addEventListener("click", function () { open(db, node.getAttribute("data-known-detection")); });
        });
    }
    window.KnownSignals = { open: open, list: list, bind: bind, settings: function (db) { list(db, true); } };
    document.addEventListener("DOMContentLoaded", function () {
        var settings = document.getElementById("alerts-settings-btn");
        if (settings) settings.addEventListener("click", function () { if (window.dashboard) list(window.dashboard, true); });
        var manager = document.getElementById("known-signals-manage");
        if (manager) manager.addEventListener("click", function () { if (window.dashboard) list(window.dashboard); });
    });
})();
