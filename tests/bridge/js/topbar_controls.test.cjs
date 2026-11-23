/* Actual dashboard/Alerts controllers: browser-only preference and timeline actions. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const test = require('node:test');
const parse5 = require('parse5');
const root = path.resolve(__dirname, '../../..');
const source = path.join(root, 'src/sigrift/bridge/static');
const settle = () => new Promise(resolve => setImmediate(resolve));

function element(id) {
    const events = {}, attrs = {};
    return {id, events, attrs, children: [], style: {}, textContent: '', innerHTML: '', hidden: false, disabled: false,
        classList: {add() {}, remove() {}},
        addEventListener(type, fn) { (events[type] ||= []).push(fn); },
        fire(type, detail = {}) { for (const fn of events[type] || []) fn({preventDefault() {}, stopPropagation() {}, ...detail}); },
        click() { if (!this.disabled) this.fire('click'); },
        setAttribute(key, value) { attrs[key] = String(value); }, getAttribute(key) { return attrs[key]; },
        appendChild(child) { this.children.push(child); child.parentNode = this; },
        removeChild(child) { this.children.splice(this.children.indexOf(child), 1); },
        querySelectorAll() { return []; }, focus() { this.focused = true; }, scrollIntoView() { this.scrolled = true; },
    };
}
function fixture({permission = 'granted', stored = null, storageFail = false, supported = true, enhancements = false} = {}) {
    const ids = ['browser-notification-toggle', 'browser-notification-state', 'alert-sound-toggle', 'alert-sound-icon',
        'toast-container', 'threat-timeline-canvas', 'threat-timeline-legend', 'threat-timeline-summary', 'threat-timeline-open', 'alerts-tab-tbody'];
    const elements = Object.fromEntries(ids.map(id => [id, element(id)]));
    const intervals = [], timers = [], audio = []; let criticalRows = 0;
    const canvas = elements['threat-timeline-canvas'];
    canvas.width = 600; canvas.height = 48; canvas.parentElement = {clientWidth: 648};
    canvas.getBoundingClientRect = () => ({left: 20, top: 10, width: 300, height: 48});
    canvas.getContext = () => new Proxy({}, {get: (obj, key) => obj[key] || (() => {})});
    const storage = new Map(stored == null ? [] : [['bridge_browser_notifications', stored]]), windowEvents = {}, notices = [];
    let prompts = 0;
    function Notification(title, options) { notices.push({title, options}); }
    Notification.permission = permission;
    Notification.requestPermission = async () => { prompts++; Notification.permission = 'granted'; return 'granted'; };
    const context = {console, document: {addEventListener() {}, getElementById: id => elements[id] || null,
        createElement: () => { const el = element(''); el.appendChild = child => { el.innerHTML += String(child.textContent).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }; return el; }, createTextNode: value => ({textContent: value}), querySelectorAll: selector => selector === '.alerts-tab-row.critical:not(.acknowledged)' ? Array(criticalRows).fill({}) : [],
        querySelector: () => null, head: element('head'), readyState: 'loading'},
        window: {fetch: async () => ({ok: true}), addEventListener(type, fn) { (windowEvents[type] ||= []).push(fn); }},
        localStorage: {getItem(key) { if (storageFail) throw Error('blocked'); return storage.get(key) || null; },
            setItem(key, value) { if (storageFail) throw Error('full'); storage.set(key, value); }},
        setTimeout(fn) { timers.push(fn); }, clearTimeout() {}, setInterval(fn, delay) { intervals.push({fn, delay}); }, clearInterval() {},
        decodeHtmlEscapedText: value => value,
    };
    if (supported) context.Notification = context.window.Notification = Notification;
    for (const name of ['dashboard.js', 'alerts.js']) vm.runInNewContext(fs.readFileSync(path.join(source, name), 'utf8'), context, {filename: path.join(source, name)});
    const db = Object.create(context.BridgeDashboard.prototype), activations = [];
    db.apiFetch = async () => [];
    db.activateTab = name => activations.push(name);
    context.window.dashboard = db;
    context.window.AudioContext = function() {
        const record = {starts: 0, closes: 0}; audio.push(record);
        this.currentTime = 0; this.destination = {};
        this.createOscillator = () => ({connect() {}, frequency: {}, start() {record.starts++;}, stop() {}});
        this.createGain = () => ({connect() {}, gain: {}});
        this.close = () => {record.closes++; return Promise.resolve();};
    };
    if (enhancements) vm.runInNewContext(fs.readFileSync(path.join(source, 'ux_enhancements.js'), 'utf8'), context, {filename: path.join(source, 'ux_enhancements.js')});
    return {db, context, elements, canvas, storage, Notification, notices, audio, timers,
        prompts: () => prompts, windowEvents, activations,
        summary: () => elements['threat-timeline-summary'].textContent,
        toasts: () => elements['toast-container'].children.map(child => child.textContent),
        init() { db._initBrowserNotifications(); return this; },
        timeline() { db._initThreatTimeline(); return this; }};
}

test('notification button is immediately after audio in shipped markup', () => {
    const html = fs.readFileSync(path.join(root, 'src/sigrift/bridge/templates/index.html'), 'utf8');
    assert.match(html, /id="alert-sound-toggle"[\s\S]*?<\/button>\s*<button[^>]*id="browser-notification-toggle"/);
});

test('initialization and incoming alerts never prompt for permission', () => {
    const f = fixture({permission: 'default'}); f.db._initAlertSound(); f.db._browserNotify('warning', 'Real alert');
    assert.equal(f.prompts(), 0); assert.equal(f.notices.length, 0);
});

test('granted notifications can be disabled and stay off after reload independently of audio', () => {
    const f = fixture().init(); f.db._browserNotify('warning', 'First'); assert.equal(f.notices.length, 1);
    f.elements['browser-notification-toggle'].click(); f.db._browserNotify('critical', 'Second');
    assert.equal(f.notices.length, 1); assert.equal(f.storage.get('bridge_browser_notifications'), 'off');
    assert.equal(f.storage.has('bridge_alert_sound'), false);
    assert.equal(f.elements['browser-notification-toggle'].getAttribute('aria-pressed'), 'false');
    const reload = fixture({stored: f.storage.get('bridge_browser_notifications')}).init();
    reload.db._browserNotify('warning', 'Reload'); assert.equal(reload.notices.length, 0);
    reload.elements['browser-notification-toggle'].click(); reload.db._browserNotify('warning', 'Enabled');
    assert.equal(reload.notices.length, 1);
});

test('only explicit enable asks once while permission is pending', async () => {
    const f = fixture({permission: 'default'}).init(); let resolve;
    f.Notification.requestPermission = () => { f.requested = (f.requested || 0) + 1; return new Promise(done => {resolve = done;}); };
    f.elements['browser-notification-toggle'].click(); f.elements['browser-notification-toggle'].click();
    assert.equal(f.requested, 1); assert.equal(f.elements['browser-notification-toggle'].disabled, true);
    f.Notification.permission = 'granted'; resolve('granted'); await settle();
    assert.equal(f.elements['browser-notification-toggle'].disabled, false); assert.equal(f.notices.length, 0);
    f.db._browserNotify('critical', '<b>Literal</b>'); assert.equal(f.notices[0].options.body, '<b>Literal</b>');
});

for (const permission of ['denied', 'default']) test('ungranted response remains off: ' + permission, async () => {
    const f = fixture({permission: 'default'}).init();
    f.Notification.requestPermission = async () => {f.Notification.permission = permission; return permission;};
    f.elements['browser-notification-toggle'].click(); await settle(); f.db._browserNotify('critical', 'No permission');
    assert.equal(f.notices.length, 0); assert.equal(f.elements['browser-notification-toggle'].getAttribute('aria-pressed'), 'false');
});

test('denied permission reports browser settings without another prompt', () => {
    const f = fixture({permission: 'denied'}).init(); f.elements['browser-notification-toggle'].click();
    assert.equal(f.prompts(), 0); assert.match(f.toasts().join(' '), /browser.*settings/i);
});

test('unsupported API is visibly unavailable and never interrupts dashboard actions', () => {
    const f = fixture({supported: false}).init(); f.db._browserNotify('critical', 'No support');
    assert.equal(f.elements['browser-notification-toggle'].disabled, true);
    assert.match(f.elements['browser-notification-state'].textContent, /unavailable/i);
});

for (const mode of ['throw', 'reject']) test('permission error is bounded and permits retry: ' + mode, async () => {
    const f = fixture({permission: 'default'}).init();
    f.Notification.requestPermission = () => {if (mode === 'throw') throw Error('policy'); return Promise.reject(Error('policy'));};
    f.elements['browser-notification-toggle'].click(); await settle();
    assert.equal(f.elements['browser-notification-toggle'].disabled, false);
    assert.equal(f.elements['browser-notification-toggle'].getAttribute('aria-pressed'), 'false');
    assert.match(f.toasts().join(' '), /could not|unable/i);
});

test('failed storage still disables this tab and truthfully reports lack of persistence', () => {
    const f = fixture({storageFail: true}).init(); f.elements['browser-notification-toggle'].click();
    f.db._browserNotify('warning', 'Muted'); assert.equal(f.notices.length, 0);
    assert.match(f.toasts().join(' '), /this tab|not.*saved|cannot.*save/i);
});

test('a storage event updates another tab and browser permission revocation is respected', () => {
    const f = fixture().init(); f.storage.set('bridge_browser_notifications', 'off');
    for (const fn of f.windowEvents.storage) fn({key: 'bridge_browser_notifications'});
    f.db._browserNotify('warning', 'Muted elsewhere'); assert.equal(f.notices.length, 0);
    f.storage.set('bridge_browser_notifications', 'on');
    for (const fn of f.windowEvents.storage) fn({key: 'bridge_browser_notifications'});
    f.Notification.permission = 'denied'; f.db._browserNotify('warning', 'Revoked'); assert.equal(f.notices.length, 0);
});

test('browser mute preserves dashboard refresh, toast, critical banner and independent audio', () => {
    const f = fixture({stored: 'off'}).init(), calls = [];
    f.db._loadAlerts = () => calls.push('refresh'); f.db._pushThreatEvent = () => calls.push('timeline');
    f.db._playAlertTone = () => calls.push('audio'); f.context.showCriticalBanner = () => calls.push('banner');
    f.db._onAlertWS({alert_id: 'real-id', severity: 'critical', message: 'Actual dashboard alert'});
    assert.deepEqual(calls, ['refresh', 'timeline', 'audio', 'banner']); assert.equal(f.notices.length, 0);
    assert.ok(f.toasts().includes('Actual dashboard alert'));
});

test('alert tone stays silent while the Alerts tab is open and visible', () => {
    const f = fixture({}).init(), calls = [];
    f.db._loadAlerts = () => {}; f.db._pushThreatEvent = () => {};
    f.db._playAlertTone = () => calls.push('audio'); f.context.showCriticalBanner = () => calls.push('banner');
    f.db.alertsDashboard = {_active: true, _fetchAlerts: () => calls.push('feed')};
    f.db._onAlertWS({alert_id: 'seen', severity: 'critical', message: 'Seen on the Alerts tab'});
    assert.deepEqual(calls, ['feed', 'banner']);
    f.db.alertsDashboard._active = false;
    f.db._onAlertWS({alert_id: 'away', severity: 'critical', message: 'Elsewhere'});
    assert.ok(calls.includes('audio'));
});

function events(f) {
    const now = Date.now();
    f.db._tlEvents = [{ts: now - 15 * 60000, protocol: 'alert', severity: 'critical', label: '<img src=x onerror=bad()>', alertId: 'actual-id'},
        {ts: now - 10 * 60000, protocol: 'wifi', severity: 'warning', label: 'Observed Wi-Fi'},
        {ts: now - 5 * 60000, protocol: 'alert', severity: 'info', label: 'Other actual alert', alertId: 'other-id'}];
    f.db._renderThreatTimeline();
}

test('scaled canvas hover describes actual alert literally; click opens and focuses its actual ID', () => {
    const f = fixture().timeline(); events(f); const focused = [];
    f.db.alertsDashboard = {focusAlert: id => focused.push(id)};
    f.canvas.fire('mousemove', {clientX: 170, clientY: 16});
    assert.match(f.summary(), /critical/i); assert.match(f.summary(), /<img src=x onerror=bad\(\)>/);
    assert.equal(f.elements['threat-timeline-summary'].innerHTML, '');
    f.canvas.fire('click', {clientX: 170, clientY: 16});
    assert.deepEqual(f.activations, ['alerts']); assert.deepEqual(focused, ['actual-id']);
});

test('observation hover is explicitly unlinked and does not navigate to a fabricated alert', () => {
    const f = fixture().timeline(); events(f);
    f.canvas.fire('mousemove', {clientX: 220, clientY: 27.2}); assert.match(f.summary(), /observation/i);
    f.canvas.fire('click', {clientX: 220, clientY: 27.2}); assert.equal(f.activations.length, 0);
});

test('keyboard inspects alerts and Enter opens Alerts; Escape clears detail', () => {
    const f = fixture().timeline(); events(f);
    f.canvas.fire('focus'); assert.match(f.summary(), /critical/i);
    f.canvas.fire('keydown', {key: 'ArrowRight'}); assert.match(f.summary(), /Other actual alert/);
    f.canvas.fire('keydown', {key: 'Enter'}); assert.deepEqual(f.activations, ['alerts']);
    f.canvas.fire('keydown', {key: 'Escape'}); assert.equal(f.elements['threat-timeline-summary'].hidden, true);
});

test('empty timeline retains a native Open alerts action; stale/future points cannot be selected', () => {
    const f = fixture().timeline(); const now = Date.now();
    f.db._tlEvents = [{ts: now - 31 * 60000, protocol: 'alert', label: 'Old'}, {ts: now + 60000, protocol: 'alert', label: 'Future'}];
    f.db._renderThreatTimeline(); f.canvas.fire('focus'); assert.equal(f.elements['threat-timeline-summary'].hidden, true);
    f.elements['threat-timeline-open'].click(); assert.deepEqual(f.activations, ['alerts']);
});

test('actual seeded and live alert IDs survive into timeline events', async () => {
    const f = fixture(); f.db.apiFetch = async url => url.startsWith('/api/alerts/') ? [{alert_id: 'seed-id', triggered_at: new Date().toISOString(), severity: 'warning', message: 'Seed'}] : [];
    f.timeline(); await settle(); assert.equal(f.db._tlEvents[0].alertId, 'seed-id');
    f.db._loadAlerts = () => {}; f.db._playAlertTone = () => {};
    f.db._onAlertWS({alert_id: 'live-id', severity: 'info', message: 'Live'});
    assert.equal(f.db._tlEvents.at(-1).alertId, 'live-id');
});

test('Alerts focus is an exact currently loaded row operation without changing filters', () => {
    const f = fixture(), row = element('row'), unrelated = element('other');
    row.setAttribute('data-alert-id', 'exact/"id'); unrelated.setAttribute('data-alert-id', 'other');
    f.elements['alerts-tab-tbody'].querySelectorAll = () => [unrelated, row];
    const alerts = Object.create(f.context.AlertsDashboard.prototype);
    alerts.focusAlert('missing'); assert.equal(row.focused, undefined);
    alerts.focusAlert('exact/"id'); assert.equal(row.focused, true); assert.equal(row.scrolled, true); assert.equal(unrelated.focused, undefined);
});


test('another tab disables while permission is pending: the completion cannot undo that choice', async () => {
    const f = fixture({permission: 'default'}).init(); let resolve;
    f.Notification.requestPermission = () => new Promise(done => {resolve = done;});
    f.elements['browser-notification-toggle'].click();
    f.storage.set('bridge_browser_notifications', 'off');
    for (const fn of f.windowEvents.storage) fn({key: 'bridge_browser_notifications'});
    f.Notification.permission = 'granted'; resolve('granted'); await settle();
    f.db._browserNotify('critical', 'Still muted');
    assert.equal(f.notices.length, 0); assert.equal(f.storage.get('bridge_browser_notifications'), 'off');
});

test('denied preference storage preserves per-tab audio choice independently of notifications', () => {
    const f = fixture({storageFail: true}).init(); f.db._initAlertSound();
    f.elements['alert-sound-toggle'].click(); assert.equal(f.db._alertSoundEnabled(), false);
    f.db._browserNotify('warning', 'Independent'); assert.equal(f.notices.length, 1);
    assert.equal(f.context.readBrowserPreference('unknown'), null);
});

test('a full storage quota does not undo a new tab-local preference on the next read', () => {
    const f = fixture(); f.storage.set('bridge_alert_sound', 'on');
    f.context.localStorage.setItem = () => {throw Error('QuotaExceededError');};
    f.db._initAlertSound(); f.elements['alert-sound-toggle'].click();
    assert.equal(f.db._alertSoundEnabled(), false); assert.equal(f.storage.get('bridge_alert_sound'), 'on');
    f.context.localStorage.setItem = (key, value) => f.storage.set(key, value);
    f.elements['alert-sound-toggle'].click(); assert.equal(f.db._alertSoundEnabled(), true);
});

test('browser construction policy failure does not throw or request permission', () => {
    const f = fixture().init(); function Blocked() {throw Error('Policy');} Blocked.permission = 'granted';
    f.context.Notification = f.context.window.Notification = Blocked;
    assert.doesNotThrow(() => f.db._browserNotify('critical', 'Still a dashboard alert'));
    assert.equal(f.prompts(), 0);
});

test('zero-sized canvas and a pointer away from marks do not invent an alert', () => {
    const f = fixture().timeline(); events(f);
    f.canvas.fire('mousemove', {clientX: 22, clientY: 11}); assert.equal(f.elements['threat-timeline-summary'].hidden, true);
    f.canvas.fire('click', {clientX: 22, clientY: 11}); assert.deepEqual(f.activations, []);
    f.canvas.getBoundingClientRect = () => ({width: 0, height: 0});
    f.canvas.fire('click', {clientX: 170, clientY: 16}); assert.deepEqual(f.activations, []);
});

test('a live alert without a public ID opens Alerts without fabricated row focus', () => {
    const f = fixture().timeline(), calls = [];
    f.db.alertsDashboard = {focusAlert: id => calls.push(id)};
    f.db._openTimelineAlert({protocol: 'alert'}); assert.deepEqual(f.activations, ['alerts']); assert.deepEqual(calls, []);
});

test('a refresh with no matching loaded rows consumes one-shot focus instead of retaining it indefinitely', () => {
    const f = fixture(), alerts = Object.create(f.context.AlertsDashboard.prototype);
    alerts.alerts = []; alerts._timelineFocusAlert = 'gone'; alerts._renderAlerts();
    assert.equal(alerts._timelineFocusAlert, null);
});


test('rendered untrusted alert IDs stay literal in row focus and acknowledgement attributes', async () => {
    const f = fixture(), alerts = Object.create(f.context.AlertsDashboard.prototype);
    const malicious = 'id" data-injected="bad" onclick="window.bad=1 & <tag> /#?';
    alerts.db = f.db; alerts.sortField = 'triggered_at'; alerts.sortDir = 'desc';
    alerts.alerts = [{alert_id: malicious, triggered_at: new Date().toISOString(), severity: 'warning', name: 'Literal ID', message: 'Safe text'}];
    const rows = [], buttons = [], tbody = f.elements['alerts-tab-tbody'];
    let html = '';
    Object.defineProperty(tbody, 'innerHTML', {get() {return html;}, set(value) {
        html = value; rows.length = 0; buttons.length = 0;
        const parsed = parse5.parseFragment('<table><tbody>' + value + '</tbody></table>');
        function walk(node) {
            if (node.tagName === 'tr' || node.tagName === 'button') {
                const el = element(node.tagName); for (const attr of node.attrs) el.setAttribute(attr.name, attr.value);
                (node.tagName === 'tr' ? rows : buttons).push(el);
            }
            for (const child of node.childNodes || []) walk(child);
        }
        walk(parsed);
    }});
    tbody.querySelectorAll = selector => selector === '[data-alert-id]' ? rows : buttons;
    const calls = []; f.db.apiFetch = async (url, options) => calls.push({url, options});
    alerts._fetchAlerts = () => {}; alerts._renderAlerts();
    assert.equal(rows.length, 1); assert.equal(buttons.length, 1);
    assert.equal(rows[0].getAttribute('data-alert-id'), malicious);
    assert.equal(buttons[0].getAttribute('data-ack-alert-tab'), malicious);
    for (const el of [...rows, ...buttons]) {
        assert.equal(el.getAttribute('data-injected'), undefined); assert.equal(el.getAttribute('onclick'), undefined);
    }
    alerts.focusAlert('id'); assert.equal(rows[0].focused, undefined);
    alerts.focusAlert(malicious); assert.equal(rows[0].focused, true);
    buttons[0].events.click[0].call(buttons[0]); await settle();
    const acknowledgements = calls.filter(call => call.options && call.options.method === 'PUT');
    assert.equal(acknowledgements.length, 1); assert.equal(acknowledgements[0].url, '/api/alerts/' + encodeURIComponent(malicious) + '/ack');
});

for (const storageFail of [false, true]) {
    // The dashboard plays one tone per alert it receives; nothing polls the
    // page for critical rows any more, so every tone goes through these two.
    test('every alert tone respects the audio toggle even with blocked storage: ' + storageFail, () => {
        const f = fixture({enhancements: true, storageFail}); f.db._initAlertSound();
        f.elements['alert-sound-toggle'].click();
        f.context.window._playAlertTone('warning'); f.db._playAlertTone('critical');
        assert.equal(f.audio.length, 0);
        f.elements['alert-sound-toggle'].click();
        assert.equal(f.audio.length, 0, 'unmuting replays nothing');
        f.context.window._playAlertTone('critical'); assert.equal(f.audio.length, 1); assert.ok(f.audio[0].starts > 0);
        f.db._playAlertTone('warning'); assert.equal(f.audio.length, 2);
    });
}

test('mute closes all active alarm contexts; timer cleanup is idempotent', () => {
    const f = fixture({enhancements: true}); f.db._initAlertSound();
    f.db._playAlertTone('critical'); f.context.window._playAlertTone('warning');
    assert.equal(f.audio.length, 2); f.elements['alert-sound-toggle'].click();
    assert.ok(f.audio.every(record => record.closes === 1));
    for (const fn of f.timers.splice(0)) fn();
    assert.ok(f.audio.every(record => record.closes === 1));
});

test('other-tab mute stops playback and synchronizes the visible audio toggle', () => {
    const f = fixture({enhancements: true}); f.db._initAlertSound(); f.db._playAlertTone('critical');
    f.storage.set('bridge_alert_sound', 'off');
    for (const fn of f.windowEvents.storage || []) fn({key: 'bridge_alert_sound'});
    assert.equal(f.audio[0].closes, 1);
    assert.equal(f.elements['alert-sound-toggle'].getAttribute('aria-pressed'), 'false');
    f.context.window._playAlertTone('critical'); f.db._playAlertTone('critical'); assert.equal(f.audio.length, 1);
    f.storage.set('bridge_alert_sound', 'on');
    for (const fn of f.windowEvents.focus || []) fn();
    assert.equal(f.elements['alert-sound-toggle'].getAttribute('aria-pressed'), 'true');
});

test('muted critical notification remains visible but requests silent delivery', () => {
    const f = fixture().init(); f.db._initAlertSound(); f.elements['alert-sound-toggle'].click();
    f.db._browserNotify('critical', 'Synthetic critical alert');
    assert.equal(f.notices.length, 1); assert.equal(f.notices[0].options.silent, true);
    f.elements['alert-sound-toggle'].click(); f.db._browserNotify('critical', 'Audible enabled');
    assert.equal(f.notices[1].options.silent, false);
});
