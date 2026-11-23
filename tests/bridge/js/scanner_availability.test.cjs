const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const parse5 = require('parse5');

const root = path.resolve(__dirname, '../../..');
const staticRoot = path.join(root, 'src/sigrift/bridge/static');
const html = fs.readFileSync(path.join(root, 'src/sigrift/bridge/templates/index.html'), 'utf8');
const scannerTabs = ['rf', 'spectrum-analysis', 'drone', 'iot', 'wifi', 'bluetooth', 'zigbee', 'adsb'];
const coreTabs = ['summary', 'map', 'incidents', 'threats', 'alerts', 'deployment'];

function element(id, attributes = {}, hidden = false) {
    const classes = new Set();
    return {id, hidden, disabled: hidden, style: {}, innerHTML: '', textContent: '',
        classList: {contains: name => classes.has(name), toggle: (name, yes) => yes ? classes.add(name) : classes.delete(name)},
        getAttribute: name => attributes[name], setAttribute: (name, value) => {attributes[name] = value;},
        addEventListener() {}, querySelectorAll: () => [], scrollHeight: 0, clientHeight: 0};
}

function templateElements(node, predicate) {
    return [...(predicate(node) ? [node] : []), ...(node.childNodes || []).flatMap(child => templateElements(child, predicate))];
}
function attributes(node) { return Object.fromEntries((node.attrs || []).map(attr => [attr.name, attr.value])); }
function hasClass(node, name) { return (attributes(node).class || '').split(/\s+/).includes(name); }
const template = parse5.parse(html);
const groupProtocols = {'SDR': 'sdr', 'Wi-Fi': 'wifi', 'Bluetooth SIGINT': 'bluetooth', 'Zigbee': 'zigbee'};

function controller(saved = 'summary') {
    let now = 0, nextTimer = 0;
    const timers = new Map(), storage = new Map([['bridge_active_tab', saved]]);
    const buttons = Array.from(html.matchAll(/<button([^>]*data-tab="([^"]+)"[^>]*)>/g), match =>
        element('', {'data-tab': match[2]}, /\bhidden\b/.test(match[1])));
    const tabs = buttons.map(button => element('tab-' + button.getAttribute('data-tab')));
    const groups = templateElements(template, node => hasClass(node, 'summary-group')).map(node => {
        const label = templateElements(node, item => hasClass(item, 'summary-group-label'))[0];
        const text = templateElements(label, item => item.nodeName === '#text').map(item => item.value).join('').trim();
        const attrs = attributes(node), group = element(attrs.id || text, attrs, Object.hasOwn(attrs, 'hidden'));
        group.protocol = groupProtocols[text];
        return group;
    });
    const table = element('nodes-tbody'), empty = element('nodes-empty'), count = element('node-count-badge');
    const warning = element('scanner-warning', {}, true), warningList = element('scanner-warning-list');
    const nodes = new Map([...tabs, table, empty, count, warning, warningList].map(node => [node.id, node]));
    const document = {
        addEventListener() {}, getElementById: id => nodes.get(id) || null,
        querySelectorAll: selector => selector === '#dashboard-tabs .tab-btn' ? buttons : selector === '.tab-content' ? tabs : selector === '[data-scanner-section]' ? groups.filter(group => group.getAttribute('data-scanner-section')) : [],
        querySelector: selector => selector === '#dashboard-tabs .tab-btn.active' ? buttons.find(button => button.classList.contains('active')) || null : null,
        createElement: () => ({innerHTML: '', appendChild(text) {this.innerHTML = text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');}}),
        createTextNode: text => String(text), documentElement: {scrollTop: 0},
    };
    const context = {console, document, window: {}, performance: {now: () => now},
        localStorage: {getItem: key => storage.get(key) || null, setItem: (key, value) => storage.set(key, value)},
        setTimeout: (callback, delay) => {timers.set(++nextTimer, {callback, at: now + delay}); return nextTimer;},
        clearTimeout: id => timers.delete(id), requestAnimationFrame: callback => callback(),
    };
    for (const filename of ['scanner_availability.js', 'dashboard.js']) {
        vm.runInNewContext(fs.readFileSync(path.join(staticRoot, filename), 'utf8'), context, {filename: path.join(staticRoot, filename)});
    }
    const ui = Object.create(context.BridgeDashboard.prototype);
    ui.scannerAvailability = new context.ScannerAvailability(() => {ui._updateScannerTabs(); ui._renderNodes(ui.scannerAvailability.nodes);});
    context.window.dashboard = ui;
    const calls = [];
    for (const [property, name] of [['detectionDashboard', 'rf'], ['wifiPanel', 'wifi'], ['btPanel', 'bluetooth'], ['zigbeePanel', 'zigbee']]) {
        ui[property] = {activate: () => calls.push([name, 'activate']), deactivate: () => calls.push([name, 'deactivate'])};
    }
    ui._initTabs();
    return {ui, buttons, tabs, groups, table, warning, warningList, timers, storage, calls, drillDown: context.window.drillDown,
        spyEsc(record) {
            const real = context.esc;
            context.esc = value => { record(value); return real(value); };
            return () => { context.esc = real; };
        },
        visible: () => buttons.filter(button => !button.hidden).map(button => button.getAttribute('data-tab')),
        active: () => buttons.find(button => button.classList.contains('active')).getAttribute('data-tab'),
        update: (rows, observedAt = now) => ui.scannerAvailability.update(rows, observedAt),
        tick(milliseconds) {
            const end = now + milliseconds;
            for (;;) {
                const due = [...timers.entries()].filter(([, timer]) => timer.at <= end).sort((a, b) => a[1].at - b[1].at)[0];
                if (!due) break;
                now = due[1].at; timers.delete(due[0]); due[1].callback();
            }
            now = end;
        },
    };
}

function row(protocols = [], nodeId = 'radio-one', extra = {}) {
    return {node_id: nodeId, status: 'active', last_seen: '2026-11-07T00:00:00Z',
        scanner_status: Object.fromEntries(protocols.map(protocol => [protocol, {
            protocol, state: 'running', active: true, expires_in_seconds: 120, reported_at: '2026-11-07T00:00:00Z',
        }])), ...extra};
}

test('a failed SDR remains a visible global warning while its tabs are hidden', () => {
    const c = controller(), failed = row(['sdr']);
    Object.assign(failed.scanner_status.sdr, {state: 'error', active: false, expires_in_seconds: 0});
    c.update([failed]);
    assert.ok(!c.visible().includes('rf'));
    assert.equal(c.warning.hidden, false);
    assert.match(c.warningList.innerHTML, /radio-one/);
    assert.match(c.warningList.innerHTML, /SDR.*Capture error reported/);
    assert.match(c.warningList.innerHTML, /adapter connection/);
    c.ui.activateTab('deployment');
    assert.equal(c.warning.hidden, false);
});

test('reported stop and expired capture are distinct; quiet healthy capture is not a warning', () => {
    const c = controller(), stopped = row(['wifi']);
    Object.assign(stopped.scanner_status.wifi, {state: 'stopped', active: false, expires_in_seconds: 0});
    c.update([row(['sdr']), stopped]);
    assert.match(c.warningList.innerHTML, /Wi-Fi.*Scanner stopped/);
    assert.doesNotMatch(c.warningList.innerHTML, /SDR/);
    c.tick(120000);
    assert.match(c.warningList.innerHTML, /SDR.*Scanner not reporting/);
    assert.match(c.warningList.innerHTML, /Wi-Fi.*Scanner stopped/);
});

test('failed refresh, missing reports and older/replayed healthy snapshots cannot clear a warning', () => {
    const c = controller(), failed = row(['sdr']);
    Object.assign(failed.scanner_status.sdr, {state: 'error', active: false, expires_in_seconds: 0, reported_at: '2026-11-07T00:00:02Z'});
    c.update([failed]);
    for (const snapshot of [null, [], [row([])], [row(['sdr'])]]) {
        c.tick(1000); c.update(snapshot);
        assert.equal(c.warning.hidden, false);
        assert.match(c.warningList.innerHTML, /Capture error reported/);
    }
    const replay = row(['sdr']); replay.scanner_status.sdr.reported_at = failed.scanner_status.sdr.reported_at;
    c.update([replay]);
    assert.equal(c.warning.hidden, false);
    const renewed = row(['sdr']); renewed.scanner_status.sdr.reported_at = '2026-11-07T00:00:03Z';
    c.update([renewed]);
    assert.equal(c.warning.hidden, true);
    assert.equal(c.warningList.innerHTML, '');
    assert.ok(c.visible().includes('rf'));
});

test('an omitted active scanner still schedules a warning when its retained report expires', () => {
    const c = controller(); c.update([row(['sdr'])]);
    c.tick(30000); c.update([]);
    assert.ok(!c.visible().includes('rf'));
    assert.equal(c.warning.hidden, true);
    c.tick(89999); assert.equal(c.warning.hidden, true);
    c.tick(1); // No further successful snapshot is needed to notice expiry.
    assert.equal(c.warning.hidden, false);
    assert.match(c.warningList.innerHTML, /radio-one.*SDR.*Scanner not reporting/);
    assert.equal(c.timers.size, 0);
});

test('one healthy scanner cannot hide another node failure and node text is escaped', () => {
    const c = controller(), failed = row(['sdr'], '<img src=x onerror="alert(1)">');
    Object.assign(failed.scanner_status.sdr, {state: 'error', active: false, expires_in_seconds: 0});
    c.update([row(['sdr'], 'healthy-node'), failed]);
    assert.ok(c.visible().includes('rf'));
    assert.equal(c.warning.hidden, false);
    assert.match(c.warningList.innerHTML, /&lt;img/);
    assert.doesNotMatch(c.warningList.innerHTML, /<img/);
    assert.doesNotMatch(c.warningList.innerHTML, /healthy-node/);
});

test('never-reported protocols and generic heartbeat inventory do not create scanner failures', () => {
    const c = controller();
    c.update([row([], 'inventory', {capabilities: {hardware: 'RTL-SDR', capture_mode: 'wifi'}})]);
    c.tick(300000);
    assert.equal(c.warning.hidden, true);
    assert.equal(c.warningList.innerHTML, '');
});

test('warning region is accessible and outside every gated tab and protocol section', () => {
    const warning = templateElements(template, node => attributes(node).id === 'scanner-warning')[0];
    assert.ok(warning, 'shipped warning region');
    assert.equal(attributes(warning).role, 'status');
    assert.equal(attributes(warning)['aria-live'], 'polite');
    assert.equal(attributes(warning)['aria-atomic'], 'true');
    for (let parent = warning; parent; parent = parent.parentNode) {
        assert.ok(!hasClass(parent, 'tab-content'));
        assert.equal(attributes(parent)['data-scanner-section'], undefined);
    }
});

test('all scanner navigation starts hidden, including a saved unavailable tab', () => {
    for (const saved of scannerTabs) {
        const c = controller(saved);
        assert.deepEqual(c.visible(), coreTabs);
        assert.equal(c.active(), 'summary');
        assert.ok(c.buttons.filter(button => scannerTabs.includes(button.getAttribute('data-tab'))).every(button => button.hidden && button.disabled && button.getAttribute('aria-disabled') === 'true'));
    }
});

test('host heartbeat, configured USB inventory and historical detections never enable tabs', () => {
    const c = controller();
    c.update([row([], 'monitor', {capabilities: {hardware: 'RTL-SDR', capture_mode: 'wifi', anomaly_enabled: false}, classifications_per_sec: 10, detection_summary: {total_detections: 99}})]);
    assert.deepEqual(c.visible(), coreTabs);
    assert.match(c.table.innerHTML, /> Online</);
    assert.match(c.table.innerHTML, /No active scanner reported/);
    assert.match(c.table.innerHTML, /No issues reported/);
    assert.doesNotMatch(c.table.innerHTML, /anomaly-off|> off</);
});

test('SDR enables its RF-derived views only and retains core navigation', () => {
    const c = controller(); c.update([row(['sdr'])]);
    assert.deepEqual(c.visible().filter(tab => scannerTabs.includes(tab)), ['rf', 'spectrum-analysis', 'drone', 'iot']);
    assert.ok(coreTabs.every(tab => c.visible().includes(tab)));
    assert.match(c.table.innerHTML, /SDR scanning/);
    c.ui.activateTab('rf'); assert.equal(c.active(), 'rf');
    assert.ok(c.calls.some(call => call[0] === 'rf' && call[1] === 'activate'));
});

for (const protocol of ['wifi', 'bluetooth', 'zigbee', 'adsb']) test(`${protocol} requires its own live report`, () => {
    const c = controller(); c.update([row([protocol])]);
    assert.deepEqual(c.visible().filter(tab => scannerTabs.includes(tab)), [protocol]);
    c.ui.activateTab(protocol); assert.equal(c.active(), protocol);
});

test('failed refresh preserves the existing lease, then expiry hides and deactivates without user input', () => {
    const c = controller(); c.update([row(['wifi'])]); c.ui.activateTab('wifi');
    c.tick(60000); assert.equal(c.update(null), false);
    assert.equal(c.active(), 'wifi'); assert.ok(c.visible().includes('wifi'));
    c.tick(60000);
    assert.equal(c.active(), 'summary'); assert.ok(!c.visible().includes('wifi'));
    assert.equal(c.storage.get('bridge_active_tab'), 'summary');
    assert.match(c.table.innerHTML, /No active scanner reported/);
    assert.equal(c.timers.size, 0);
    assert.ok(c.calls.some(call => call[0] === 'wifi' && call[1] === 'deactivate'));
});

for (const state of ['stopped', 'error']) test(`${state} immediately removes navigation and deep-link activation`, () => {
    const c = controller(); c.update([row(['zigbee'])]); c.ui.activateTab('zigbee');
    const stopped = row(['zigbee']); Object.assign(stopped.scanner_status.zigbee, {state, active: false, expires_in_seconds: 0});
    c.update([stopped]);
    assert.equal(c.active(), 'summary');
    c.ui.activateTab('zigbee'); assert.equal(c.active(), 'summary');
    c.ui.activateTab('bad"]selector'); assert.equal(c.active(), 'summary');
});

test('duplicate snapshots cannot extend a lease; a genuinely new report can', () => {
    const c = controller(); c.update([row(['wifi'])]); c.tick(90000);
    c.update([row(['wifi'])]); c.tick(30000);
    assert.ok(!c.visible().includes('wifi'));
    const renewed = row(['wifi']); renewed.scanner_status.wifi.reported_at = '2026-11-07T00:02:00Z';
    c.update([renewed]); c.tick(119999); assert.ok(c.visible().includes('wifi'));
    c.tick(1); assert.ok(!c.visible().includes('wifi'));
});

test('request time bounds slow responses and older in-flight snapshots are ignored', () => {
    const c = controller(); c.tick(121000);
    c.update([row(['wifi'])], 0); assert.ok(!c.visible().includes('wifi'));
    c.update([row(['sdr'])]);
    assert.equal(c.update([], 120000), false);
    assert.ok(c.visible().includes('rf'));
});

test('one scanner expiring does not hide the same protocol reported by another node', () => {
    const c = controller(), first = row(['wifi']), second = row(['wifi'], 'radio-two');
    first.scanner_status.wifi.expires_in_seconds = 30;
    c.update([first, second]); c.tick(30000); assert.ok(c.visible().includes('wifi'));
    assert.deepEqual(Array.from(c.ui.scannerAvailability.protocolsFor('radio-one')), []);
    c.tick(90000); assert.ok(!c.visible().includes('wifi'));
});

for (const patch of [{active: 'true'}, {state: 'starting'}, {protocol: 'zigbee'}, {expires_in_seconds: '120'}, {expires_in_seconds: Infinity}, {expires_in_seconds: 121}, {expires_in_seconds: 0}, {reported_at: 'invalid'}]) {
    test(`invalid runtime report stays hidden: ${JSON.stringify(patch)}`, () => {
        const c = controller(), node = row(['wifi']); Object.assign(node.scanner_status.wifi, patch);
        c.update([node]); assert.deepEqual(c.visible(), coreTabs);
    });
}

test('actual resource and scanner errors remain issues rather than being hidden by online wording', () => {
    const c = controller();
    c.update([row([], 'hot', {cpu_percent: 95}), row([], 'failed', {capabilities: {last_error: 'capture failed'}})]);
    assert.match(c.table.innerHTML, /CPU 95%/);
    assert.match(c.table.innerHTML, /capture failed/);
    assert.match(c.table.innerHTML, /issue-error/);
});

for (const [filename, selector] of [['adsb.js', '#aircraft-table tbody'], ['drone.js', '#drone-table tbody'], ['iot.js', 'zwave-devices']]) {
    test(`${filename} does not poll an unavailable scanner`, async () => {
        const calls = [], node = {innerHTML: '', textContent: ''};
        const context = {console, window: {dashboard: {isTabAvailable: () => false}},
            document: {querySelector: value => value === selector ? node : null, getElementById: value => value === selector ? node : null},
            setInterval() {}, fetch: async (...args) => {calls.push(args); return {ok: true, json: async () => ({})};},
            sessionStorage: {getItem: () => null},
        };
        vm.runInNewContext(fs.readFileSync(path.join(staticRoot, filename), 'utf8'), context, {filename: path.join(staticRoot, filename)});
        await new Promise(resolve => setImmediate(resolve));
        assert.deepEqual(calls, []);
    });
}


test('a replayed expired report cannot revive navigation, including after timer removal', () => {
    const c = controller(); c.update([row(['wifi'])]); c.tick(120000);
    c.update([row(['wifi'])]); assert.ok(!c.visible().includes('wifi'));
});

test('older runtime snapshots cannot undo a newer stop or replace a renewal', () => {
    const c = controller(); c.update([row(['wifi'])]); c.tick(1000);
    const stopped = row(['wifi']); Object.assign(stopped.scanner_status.wifi, {
        state: 'stopped', active: false, expires_in_seconds: 0, reported_at: '2026-11-07T00:00:01Z',
    });
    c.update([stopped]); c.tick(1000); c.update([row(['wifi'])]);
    assert.ok(!c.visible().includes('wifi'));
    const renewed = row(['wifi']); renewed.scanner_status.wifi.reported_at = '2026-11-07T00:00:02Z';
    c.update([renewed]); c.tick(1000); c.update([stopped]);
    assert.ok(c.visible().includes('wifi'));
});


test('unavailable cross-panel drill-down returns Summary and never opens hidden detail', async () => {
    const c = controller(); c.ui.activateTab('map');
    let opened = false;
    c.ui.detectionDashboard.anomalies = [{detection_id: 'old-detection'}];
    c.ui.detectionDashboard._showDeepDive = () => { opened = true; };
    c.drillDown.toDetection('old-detection');
    await Promise.resolve();
    assert.equal(c.active(), 'summary'); assert.equal(opened, false);
    c.update([row(['sdr'])]);
    c.drillDown.toDetection('old-detection'); c.tick(180); await Promise.resolve();
    assert.equal(c.active(), 'rf'); assert.equal(opened, true);
});


for (const [filename, className, methods] of [
    ['wifi.js', 'WifiPanel', ['_loadWhitelist', '_pollNetworks', '_pollChannels', '_pollStats', '_pollWifiAnomalies']],
    ['bluetooth.js', 'BluetoothPanel', ['_loadWhitelist', '_pollDevices', '_pollStats', '_pollAnomalies']],
    ['zigbee.js', 'ZigbeePanel', ['_pollDevices', '_pollStats', '_pollTopology']],
    ['detections.js', 'DetectionDashboard', ['_fetchKPIs', '_fetchFeed', '_fetchCharts', '_fetchAnomalies', '_fetchAnomalySummary', '_initIQCaptures']],
]) test(`${filename} pending startup polling stops when scanner becomes unavailable`, () => {
    const deferred = [], calls = [];
    const context = {console, window: {}, document: {addEventListener() {}},
        setTimeout: callback => {deferred.push(callback); return 1;},
        clearTimeout() {}, setInterval: callback => {deferred.push(callback); return 1;}, clearInterval() {}, isPageActive: () => true};
    vm.runInNewContext(fs.readFileSync(path.join(staticRoot, filename), 'utf8'), context);
    const panel = Object.create(context[className].prototype);
    Object.assign(panel, {_active: true, pollTimers: {}, autoRefresh: true});
    for (const method of methods) panel[method] = () => calls.push(method);
    panel._startPolling(); assert.ok(calls.length > 0);
    panel.deactivate(); calls.length = 0;
    for (const callback of deferred) callback();
    assert.deepEqual(calls, []);
});

test('explicit scanner error remains visible independently of ordinary node health', () => {
    const c = controller(), node = row(['wifi']);
    Object.assign(node.scanner_status.wifi, {state: 'error', active: false, expires_in_seconds: 0});
    c.update([node]);
    assert.match(c.table.innerHTML, /> Online</);
    assert.match(c.table.innerHTML, /Wi-Fi scanner error/);
    assert.ok(!c.visible().includes('wifi'));
});


function visibleSummary(c) { return c.groups.filter(group => group.protocol && !group.hidden).map(group => group.protocol); }

test('protocol Summary groups start hidden and do not infer capture from historical data or heartbeat', () => {
    const c = controller();
    assert.deepEqual(visibleSummary(c), []);
    c.update([row([], 'monitor', {capabilities: {hardware: 'Bluetooth + Zigbee'}, detection_summary: {total_detections: 99}})]);
    assert.deepEqual(visibleSummary(c), []);
    assert.ok(c.groups.filter(group => group.protocol).every(group => group.getAttribute('hidden') !== undefined));
});

for (const protocol of ['sdr', 'wifi', 'bluetooth', 'zigbee']) test(`quiet ${protocol} capture enables only its Summary group`, () => {
    const c = controller();
    c.update([row([protocol], 'quiet-radio', {detection_summary: {total_detections: 0}})]);
    assert.deepEqual(visibleSummary(c), [protocol]);
    assert.ok(coreTabs.every(tab => c.visible().includes(tab)));
});

test('actual failed node fetch preserves Summary lease grace then expires groups', async () => {
    const c = controller(); c.update([row(['bluetooth', 'zigbee'])]);
    c.ui.apiFetch = async () => { throw new Error('network unavailable'); };
    c.tick(60000); c.ui._pollNodes(); await new Promise(resolve => setImmediate(resolve));
    assert.deepEqual(visibleSummary(c), ['bluetooth', 'zigbee']);
    c.tick(60000); assert.deepEqual(visibleSummary(c), []);
});

for (const state of ['stopped', 'error']) test(`${state} removes only that Summary group without deleting stored values`, () => {
    const c = controller(); c.update([row(['wifi', 'bluetooth'])]);
    const group = c.groups.find(group => group.protocol === 'bluetooth');
    group.innerHTML = '<div>Stored count: 24</div>';
    const stopped = row(['wifi', 'bluetooth']);
    Object.assign(stopped.scanner_status.bluetooth, {state, active: false, expires_in_seconds: 0, reported_at: '2026-11-07T00:00:01Z'});
    c.update([stopped]);
    assert.deepEqual(visibleSummary(c), ['wifi']);
    assert.equal(group.innerHTML, '<div>Stored count: 24</div>');
});

test('stale and replayed reports cannot expose Summary groups', () => {
    const c = controller(); c.tick(121000); c.update([row(['zigbee'])], 0);
    assert.deepEqual(visibleSummary(c), []);
    const current = row(['zigbee']); current.scanner_status.zigbee.reported_at = '2026-11-07T00:02:01Z';
    c.update([current]); assert.deepEqual(visibleSummary(c), ['zigbee']);
    c.tick(120000); c.update([current]); assert.deepEqual(visibleSummary(c), []);
});

test('another live node keeps the protocol Summary group visible after one lease expires', () => {
    const c = controller(), first = row(['bluetooth']), second = row(['bluetooth'], 'second');
    first.scanner_status.bluetooth.expires_in_seconds = 1;
    c.update([first, second]); c.tick(1000); assert.deepEqual(visibleSummary(c), ['bluetooth']);
    c.tick(119000); assert.deepEqual(visibleSummary(c), []);
});

test('generic node and alert health, setup and stored history remain outside scanner gating', () => {
    for (const id of ['stat-nodes', 'stat-alerts', 'panel-nodes', 'panel-alerts', 'panel-activity', 'panel-unique-freqs', 'panel-suspicious-freqs', 'panel-active-freqs']) {
        let node = templateElements(template, node => attributes(node).id === id)[0];
        assert.ok(node, id + ' remains present');
        for (; node; node = node.parentNode) {
            assert.equal(attributes(node)['data-scanner-section'], undefined, id + ' must remain available');
            assert.ok(!hasClass(node, 'summary-group') || !templateElements(node, n => hasClass(n, 'summary-group-label')).some(n => groupProtocols[templateElements(n, t => t.nodeName === '#text').map(t => t.value).join('').trim()]), id + ' is not a protocol metric');
        }
    }
});

// Status reasons sent with an "error" report (sensor lifecycle contract).
const scannerLabels = {sdr: 'SDR', wifi: 'Wi-Fi', bluetooth: 'Bluetooth', zigbee: 'Zigbee', adsb: 'ADS-B'};
function failing(protocol, reason, reportedAt = '2026-11-07T00:00:00Z', nodeId = 'radio-one') {
    const node = row([protocol], nodeId);
    Object.assign(node.scanner_status[protocol], {state: 'error', active: false, expires_in_seconds: 0, reported_at: reportedAt, reason});
    return node;
}
function countWrites(element) {
    let value = element.innerHTML, writes = 0;
    Object.defineProperty(element, 'innerHTML', {get: () => value, set: next => { writes += 1; value = next; }});
    return () => writes;
}

// The advice depends on the sensor kind: Bluetooth is not part of setup and is
// never plugged in, and Zigbee and ADS-B select their sensor themselves.
const advice = {
    sensor_absent: {
        sdr: 'The SDR sensor is not connected. Reconnect it to the same USB port and capture resumes by itself. If it is on another port, run setup again on this node.',
        wifi: 'The Wi-Fi sensor is not connected. Reconnect it to the same USB port and capture resumes by itself. If it is on another port or came back under another interface name, run setup again on this node.',
        bluetooth: 'The Bluetooth adapter is not available. Check that it is present and enabled on this node. Scanning resumes by itself.',
        zigbee: "The Zigbee sensor is not connected. Reconnect it to the same USB port and capture resumes by itself. If it is on another port, select it again in the Zigbee scanner's own configuration.",
        adsb: "The ADS-B sensor is not connected. Reconnect it to the same USB port and capture resumes by itself. If it is on another port, select it again in the ADS-B scanner's own configuration.",
    },
    sensor_changed: {
        sdr: 'A different SDR sensor is connected where the selected one was. Run setup again on this node to use it.',
        wifi: 'A different Wi-Fi sensor is connected where the selected one was. Run setup again on this node to use it.',
        bluetooth: 'A different Bluetooth adapter is in place of the selected one. Set MLRF_BT_ADAPTER to the adapter you want and restart the Bluetooth scanner.',
        zigbee: "A different Zigbee sensor is connected where the selected one was. Select it in the Zigbee scanner's own configuration to use it.",
        adsb: "A different ADS-B sensor is connected where the selected one was. Select it in the ADS-B scanner's own configuration to use it.",
    },
    sensor_unusable: {
        sdr: 'The SDR sensor is connected, but the scanner cannot open it. Prepare it on this node again with scanner_setup.py prepare-rtl. QUICKSTART explains how to make that last across re-plugs.',
        wifi: 'The Wi-Fi sensor is connected, but the scanner cannot open it. Prepare it on this node again.',
        bluetooth: 'The Bluetooth adapter is connected, but the scanner cannot open it. Prepare it on this node again.',
        zigbee: 'The Zigbee sensor is connected, but the scanner cannot open it. Prepare it on this node again.',
        adsb: 'The ADS-B sensor is connected, but the scanner cannot open it. Prepare it on this node again.',
    },
};
const reasonTitle = {sensor_absent: 'Sensor not connected', sensor_changed: 'Different sensor connected', sensor_unusable: 'Sensor cannot be opened'};
const reasonCell = {sensor_absent: 'sensor not connected', sensor_changed: 'sensor changed', sensor_unusable: 'sensor cannot be opened'};
const quoted = text => text.replace(/'/g, '&#39;');

for (const [protocol, label] of Object.entries(scannerLabels)) {
    for (const reason of Object.keys(advice)) {
        test(`${protocol}: ${reason} gives advice for that kind of sensor`, () => {
            const c = controller(); c.update([failing(protocol, reason)]);
            assert.equal(c.warning.hidden, false);
            assert.ok(c.warningList.innerHTML.includes(`radio-one · ${label} — ${reasonTitle[reason]}</strong>. ${quoted(advice[reason][protocol])} Status reported at:`),
                c.warningList.innerHTML);
            assert.doesNotMatch(c.warningList.innerHTML, /Capture error reported/);
            assert.ok(c.table.innerHTML.includes(`${label} ${reasonCell[reason]}`));
        });
    }
    // Wording that would mislead for this kind of sensor.
    test(`${protocol}: the advice names only the fix that works for it`, () => {
        const c = controller(); c.update(Object.keys(advice).map((reason, index) => failing(protocol, reason, undefined, 'node-' + index)));
        const text = c.warningList.innerHTML;
        if (protocol === 'bluetooth') assert.doesNotMatch(text, /plug|USB port|Run setup|run setup/);
        else assert.doesNotMatch(text, /MLRF_BT_ADAPTER/);
        if (protocol === 'zigbee' || protocol === 'adsb') assert.doesNotMatch(text, /setup/);
        if (protocol !== 'sdr') assert.doesNotMatch(text, /prepare-rtl|QUICKSTART/);
        if (protocol !== 'wifi') assert.doesNotMatch(text, /interface name/);
    });
    test(`${protocol}: starting capture is neither a warning nor an issue`, () => {
        const c = controller(); c.update([failing(protocol, 'starting')]);
        assert.equal(c.warning.hidden, true);
        assert.equal(c.warningList.innerHTML, '');
        assert.match(c.table.innerHTML, new RegExp(label + ' starting capture'));
        assert.match(c.table.innerHTML, /No issues reported/);
        assert.doesNotMatch(c.table.innerHTML, /issue-error|scanner error/);
    });
    for (const reason of ['capture_failed', null, undefined, 'usb_gremlins', 'constructor']) {
        test(`${protocol}: reason ${reason} keeps the existing error wording`, () => {
            const c = controller(); c.update([failing(protocol, reason)]);
            assert.ok(c.warningList.innerHTML.includes(`${label} — Capture error reported</strong>. Check scanner logs, adapter connection and device permissions.`));
            assert.ok(c.table.innerHTML.includes(`${label} scanner error`));
            assert.doesNotMatch(c.warningList.innerHTML + c.table.innerHTML, /usb_gremlins|constructor|not connected|Different sensor|cannot be opened/);
        });
    }
}

test('a reason only explains an error report', () => {
    const c = controller(), stopped = row(['wifi']);
    Object.assign(stopped.scanner_status.wifi, {state: 'stopped', active: false, expires_in_seconds: 0, reason: 'sensor_absent'});
    c.update([stopped]);
    assert.match(c.warningList.innerHTML, /Wi-Fi — Scanner stopped/);
    assert.doesNotMatch(c.warningList.innerHTML, /not connected/);
});

test('the banner names the status report time and is not rewritten while only that time advances', () => {
    const c = controller(), writes = countWrites(c.warningList);
    c.update([failing('sdr', 'sensor_absent', '2026-11-07T00:00:00Z')]);
    assert.equal(writes(), 1);
    assert.match(c.warningList.innerHTML, /Status reported at: 2026-11-07T00:00:00.000Z\.<\/li>/);
    assert.doesNotMatch(c.warningList.innerHTML, /capture report/i);
    for (const second of ['30', '59']) {
        c.tick(30000); c.update([failing('sdr', 'sensor_absent', `2026-11-07T00:00:${second}Z`)]);
    }
    assert.equal(writes(), 1);
    // A different cause is a new warning and is announced.
    c.update([failing('sdr', 'sensor_changed', '2026-11-07T00:01:00Z')]);
    assert.equal(writes(), 2);
    assert.match(c.warningList.innerHTML, /Different sensor connected.*Status reported at: 2026-11-07T00:01:00.000Z/);
});

test('an expired scanner names its last status report', () => {
    const c = controller(); c.update([row(['wifi'])]); c.tick(120000);
    assert.match(c.warningList.innerHTML, /Scanner not reporting.*Last status report: 2026-11-07T00:00:00.000Z\./);
});

test('a replayed report may drop a reason but cannot substitute another', () => {
    const c = controller(); c.update([failing('wifi', 'sensor_absent')]);
    c.update([failing('wifi', 'sensor_changed')]);
    assert.match(c.warningList.innerHTML, /Capture error reported/);
    assert.doesNotMatch(c.warningList.innerHTML, /Different sensor/);
    c.update([failing('wifi', 'sensor_changed', '2026-11-07T00:00:30Z')]);
    assert.match(c.warningList.innerHTML, /Different sensor connected/);
    c.update([failing('wifi', null, '2026-11-07T00:00:30Z')]);
    assert.match(c.warningList.innerHTML, /Capture error reported/);
});

test('a reconnected sensor clears its warning from the next node poll, without a reload', async () => {
    const c = controller(), replies = [[failing('bluetooth', 'sensor_absent')]];
    c.ui.apiFetch = async () => replies.shift();
    c.ui._pollNodes(); await new Promise(resolve => setImmediate(resolve));
    assert.equal(c.warning.hidden, false);
    assert.ok(!c.visible().includes('bluetooth'));
    const recovered = row(['bluetooth']); recovered.scanner_status.bluetooth.reported_at = '2026-11-07T00:00:30Z';
    replies.push([recovered]); c.tick(10000);
    c.ui._pollNodes(); await new Promise(resolve => setImmediate(resolve));
    assert.equal(c.warning.hidden, true);
    assert.equal(c.warningList.innerHTML, '');
    assert.ok(c.visible().includes('bluetooth'));
    assert.match(c.table.innerHTML, /Bluetooth scanning/);
    assert.doesNotMatch(c.table.innerHTML, /not connected/);
});

test('a reconnected sensor clears its warning from a WebSocket snapshot', () => {
    const c = controller(); c.ui._markDataFresh = () => {};
    c.ui._onStatusWS({type: 'snapshot', nodes: [failing('zigbee', 'sensor_changed')]});
    assert.match(c.warningList.innerHTML, /Zigbee — Different sensor connected/);
    const recovered = row(['zigbee']); recovered.scanner_status.zigbee.reported_at = '2026-11-07T00:00:30Z';
    c.tick(1000); c.ui._onStatusWS({type: 'snapshot', nodes: [recovered]});
    assert.equal(c.warning.hidden, true);
    assert.ok(c.visible().includes('zigbee'));
});

test('node ids with markup are escaped in the warning banner and the node table', () => {
    const c = controller(), id = '<img src=x onerror=alert(1)>';
    c.update(Object.keys(advice).map(reason => failing('sdr', reason, undefined, id + reason)).concat([failing('wifi', 'starting', undefined, id)]));
    assert.equal(c.warning.hidden, false);
    for (const html of [c.warningList.innerHTML, c.table.innerHTML]) {
        assert.doesNotMatch(html, /<img/);
        assert.match(html, /&lt;img src=x onerror=alert\(1\)&gt;/);
    }
    assert.match(c.warningList.innerHTML, /&lt;img src=x onerror=alert\(1\)&gt;sensor_unusable · SDR — Sensor cannot be opened/);
});

test('the new banner and node table strings go through esc()', () => {
    // A node id cannot reach these strings, so check the escaping call itself:
    // dropping esc() around them would otherwise go unnoticed.
    const c = controller(), escaped = new Set(), restore = c.spyEsc(value => escaped.add(String(value)));
    c.update([failing('sdr', 'sensor_unusable', undefined, 'radio-one'), failing('wifi', 'starting', undefined, 'radio-two'),
        failing('bluetooth', 'sensor_absent', undefined, 'radio-three')]);
    restore();
    assert.ok(escaped.has(advice.sensor_unusable.sdr));
    assert.ok(escaped.has(advice.sensor_absent.bluetooth));
    assert.ok(escaped.has('Wi-Fi starting capture'));
    assert.ok(escaped.has('SDR sensor cannot be opened'));
});
