/* The shipped Bluetooth SIGINT panel (bluetooth.js) built from index.html:
 * device table, search and authorization filters, whitelisting, the anomaly
 * queue with its single and bulk actions, and live updates. Device names and
 * manufacturers are advertised by whoever is in range, and often missing. */
const assert = require('node:assert/strict');
const test = require('node:test');
const { bootDashboard, response, injected, settle } = require('./untrusted_dom.cjs');

const MARKUP = '<img src=x onerror=alert(1)><script>alert(2)</script>';
const NOT_JSON = () => response(503, '<html>unavailable</html>', 'text/html');
const T1 = new Date(2026, 10, 10, 9, 0).toISOString();
const A1 = 'AA:00:00:00:00:01', A2 = 'AA:00:00:00:00:02', A3 = 'AA:00:00:00:00:03', A4 = 'AA:00:00:00:00:04';

function panel({ devices = [], anomalies = [], whitelist = { whitelist: [] }, routes = () => undefined, activate = true,
    ids = [], subtrees = [], scripts = [], ...options } = {}) {
    const f = bootDashboard({ ids: ['panel-bluetooth', 'sum-bt-devices', 'sum-bt-anomalies', ...ids], subtrees: ['panel-bluetooth', ...subtrees],
        scripts: [...scripts, 'bluetooth.js'], ...options, routes: (url, opts, call) => {
            const answer = routes(url, opts, call);
            if (answer !== undefined) return answer;
            if (opts.method && opts.method !== 'GET') return {};
            if (url.startsWith('/api/admin/bt-whitelist')) return whitelist;
            if (url.startsWith('/api/bluetooth/devices')) return { devices };
            if (url.startsWith('/api/bluetooth/anomalies?min_score=0.3')) return anomalies instanceof Array ? { anomalies, total: anomalies.length } : anomalies;
            return undefined;
        } });
    f.bt = f.db.btPanel;
    if (activate) f.bt.activate();
    return f;
}
const rows = f => f.el('bt-device-tbody').querySelectorAll('.bt-dev-row');
const cells = row => row.querySelectorAll('td').map(td => td.textContent);
const urls = (f, prefix) => f.requests.map(call => call.url.replace(/[?&]_t=\d+$/, '')).filter(url => url.startsWith(prefix));
const cards = f => f.el('bt-anomaly-queue').querySelectorAll('.anomaly-card');
const search = (f, text) => { const input = f.el('bt-manufacturer-search'); input.value = text; input.dispatchEvent(new f.context.Event('input')); };
const change = (f, el, value) => { el.value = value; el.dispatchEvent(new f.context.Event('change')); };
const short = iso => new Date(iso).toLocaleString(undefined, { hour12: false, month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' });
/* Bluetooth events on the cross-protocol threat timeline (seeded alerts aside). */
const btEvents = f => JSON.parse(JSON.stringify(f.db._tlEvents)).filter(event => ['bt', 'bluetooth'].includes(event.protocol))
    .map(event => [event.severity, event.label]);

const DEVICES = [
    { device_addr: A1, device_name: 'Watch', manufacturer: 'Acme', device_type: 'ble', rssi_dbm: -45.4, node_ids: ['n1', 'n2'],
        service_uuids: ['180d', '180f'], last_seen: T1 },
    { device_addr: A2, device_name: 'Speaker', manufacturer: 'Sonic', device_type: 'classic', rssi_dbm: -65, node_id: 'n3', timestamp: T1 },
    { device_addr: A3, device_type: 'dual', rssi_dbm: -80 },
    { device_addr: A4, device_name: MARKUP, device_type: 'weird' }];

test('device rows show type, signal strength, nodes and services, with placeholders for what was not advertised', async () => {
    const f = panel({ devices: DEVICES, whitelist: {} });
    await settle();
    assert.equal(f.el('bt-device-count-badge').textContent, '4');
    assert.equal(f.el('bt-device-empty').style.display, 'none');
    assert.deepEqual(rows(f).map(cells), [
        [A1, 'Watch', 'BLE', 'Acme', '-45.4 dBm', 'n1 n2 ', '2 svc', short(T1), 'Whitelist'],
        [A2, 'Speaker', 'Classic', 'Sonic', '-65.0 dBm', 'n3 ', '--', short(T1), 'Whitelist'],
        [A3, '(unnamed)', 'Dual', '--', '-80.0 dBm', '--', '--', '--', 'Whitelist'],
        [A4, MARKUP, 'Unknown', '--', '-- dBm', '--', '--', '--', 'Whitelist']], 'strongest first; an unknown RSSI sorts last');
    assert.deepEqual(rows(f).map(row => row.querySelectorAll('td')[4].style.color),
        ['var(--accent-green)', 'var(--accent-yellow)', 'var(--accent-red)', 'var(--accent-red)']);
    assert.deepEqual(injected(f.el('bt-device-tbody')), []);
    rows(f)[1].querySelector('td').click();
    assert.deepEqual(rows(f).map(row => row.style.background), ['', 'var(--bg-hover)', '', '']);
    f.answerConfirm(false);
    rows(f)[0].querySelector('[data-bt-wl-addr]').click();
    assert.equal(rows(f)[0].style.background, '', 'the Whitelist button does not select the row');
});

test('the signal colour turns from green to yellow at -50 dBm and to red at -70 dBm', async () => {
    const f = panel({ devices: [-49.9, -50, -69.9, -70].map((rssi_dbm, i) => ({ device_addr: 'CC:00:00:00:00:0' + i, rssi_dbm })) });
    await settle();
    assert.deepEqual(rows(f).map(row => [cells(row)[4], row.querySelectorAll('td')[4].style.color]), [['-49.9 dBm', 'var(--accent-green)'],
        ['-50.0 dBm', 'var(--accent-yellow)'], ['-69.9 dBm', 'var(--accent-yellow)'], ['-70.0 dBm', 'var(--accent-red)']]);
});

test('whitelisting a named device sends and announces its name', async () => {
    const f = panel({ devices: DEVICES });
    await settle();
    rows(f)[0].querySelector('[data-bt-wl-addr]').click();
    await settle();
    assert.deepEqual(f.body(f.lastWrite()), { device_addr: A1, device_name: 'Watch' });
    assert.equal(f.toasts().at(-1), 'Whitelisted Watch');
});

test('a whitelisted device shows as authorized once the whitelist has reloaded', async () => {
    let whitelist = { whitelist: [] };
    const f = panel({ devices: DEVICES, routes: (url, opts) => (url.startsWith('/api/admin/bt-whitelist') && (opts.method || 'GET') === 'GET' ? whitelist : undefined) });
    await settle();
    whitelist = { whitelist: [{ device_addr: A1, id: 9 }] };
    rows(f)[0].querySelector('[data-bt-wl-addr]').click();
    await settle();
    assert.equal(cells(rows(f)[0])[8], 'Authorized');
});

test('manufacturer search, the authorization filter and whitelisting narrow and update the device table', async () => {
    let whitelist = { whitelist: [{ device_addr: A2.toLowerCase(), id: 3 }] }, add = {};
    const f = panel({ devices: DEVICES, routes: (url, opts) => {
        if (url.startsWith('/api/admin/bt-whitelist')) return opts.method === 'POST' ? add : whitelist;
        return undefined;
    } });
    await settle();
    const addrs = () => rows(f).map(row => row.getAttribute('data-addr'));
    search(f, '  ACME ');
    assert.deepEqual(addrs(), [A1], 'search is trimmed and case-insensitive');
    search(f, 'speak');
    assert.deepEqual(addrs(), [A2], 'search also matches the device name');
    search(f, '');
    change(f, f.el('bt-device-show-select'), 'authorized');
    assert.deepEqual(addrs(), [A2]);
    assert.equal(rows(f)[0].querySelector('.admin-badge:not([data-bt-wl-addr])').textContent, 'Classic');
    assert.equal(rows(f)[0].querySelectorAll('td')[8].textContent, 'Authorized');
    change(f, f.el('bt-device-show-select'), 'unauthorized');
    assert.deepEqual(addrs(), [A1, A3, A4]);
    search(f, 'sonic');
    assert.equal(f.el('bt-device-tbody').textContent, 'No unauthorized devices');
    search(f, '');

    f.answerConfirm(false);
    rows(f)[0].querySelector('[data-bt-wl-addr]').click();
    assert.equal(f.dialogs.at(-1)[1], 'Whitelist BT device ' + A1 + ' (Watch)?');
    assert.equal(f.writes().length, 0);
    f.answerConfirm(true);
    whitelist = { whitelist: [...whitelist.whitelist, { device_addr: A3, id: 4 }] };
    rows(f).find(row => row.getAttribute('data-addr') === A3).querySelector('[data-bt-wl-addr]').click();
    assert.equal(f.dialogs.at(-1)[1], 'Whitelist BT device ' + A3 + '?');
    await settle();
    assert.equal(f.lastWrite().url, '/api/admin/bt-whitelist');
    assert.equal(f.lastWrite().headers['X-CSRF-Token'], 'csrf-abc123');
    assert.deepEqual(f.body(f.lastWrite()), { device_addr: A3, device_name: '' });
    assert.equal(f.toasts().at(-1), 'Whitelisted ' + A3);
    change(f, f.el('bt-device-show-select'), 'authorized');
    assert.deepEqual(addrs(), [A2, A3]);
    // A whitelist reply without entries clears what was authorized before.
    whitelist = {};
    change(f, f.el('bt-device-show-select'), 'all');
    rows(f)[0].querySelector('[data-bt-wl-addr]').click();
    await settle();
    change(f, f.el('bt-device-show-select'), 'authorized');
    assert.equal(f.el('bt-device-tbody').textContent, 'No authorized devices');
    change(f, f.el('bt-device-show-select'), 'all');
    add = NOT_JSON();
    rows(f)[0].querySelector('[data-bt-wl-addr]').click();
    await settle();
    assert.equal(f.toasts().at(-1), 'Whitelist failed: HTTP 503');
});

test('a device search without matches says no devices match', async () => {
    const f = panel({ devices: DEVICES });
    await settle();
    search(f, 'nothing-like-this');
    assert.ok(!f.el('bt-device-tbody').textContent.includes('No all devices'), f.el('bt-device-tbody').textContent);
});

test('more than 20 devices are paged behind Show all', async () => {
    const devices = Array.from({ length: 23 }, (_, i) => ({ device_addr: 'BB:00:00:00:00:' + String(i).padStart(2, '0'), rssi_dbm: -30 - i }));
    const f = panel({ devices });
    await settle();
    const toggle = f.el('bt-table-toggle');
    assert.equal(rows(f).length, 20);
    assert.ok(toggle.parentNode === f.el('bt-device-table').parentNode, 'the pager sits under the device table');
    assert.equal(toggle.textContent, 'Show all 23 devices (3 more)');
    f.el('bt-table-expand').click();
    assert.equal(rows(f).length, 23);
    assert.equal(toggle.textContent, 'Collapse to 20');
    f.el('bt-table-expand').click();
    assert.equal(rows(f).length, 20);
    devices.length = 2;
    await f.tick(15000);
    assert.equal(rows(f).length, 2);
    assert.equal(toggle.style.display, 'none');
});

test('device type buttons ask the server for that type, and failures show a retry', async () => {
    let devices = { devices: DEVICES };
    const f = panel({ routes: url => (url.startsWith('/api/bluetooth/devices') ? devices : undefined) });
    await settle();
    const button = type => f.el('bt-type-toggle').querySelectorAll('[data-bt-type]').find(b => b.getAttribute('data-bt-type') === type);
    button('ble').click();
    assert.ok(button('ble').classList.contains('active') && !button('all').classList.contains('active'));
    assert.equal(urls(f, '/api/bluetooth/devices').at(-1), '/api/bluetooth/devices?limit=200&device_type=ble');
    devices = NOT_JSON();
    button('all').click();
    await settle();
    assert.equal(urls(f, '/api/bluetooth/devices').at(-1), '/api/bluetooth/devices?limit=200');
    assert.ok(f.el('bt-device-tbody').textContent.includes('Failed to load Bluetooth devices'));
    devices = {};
    f.el('bt-device-tbody').querySelector('.retry-btn').click();
    await settle();
    assert.equal(f.el('bt-device-tbody').textContent, '');
    assert.equal(f.el('bt-device-empty').style.display, '');
    assert.equal(f.el('bt-device-count-badge').textContent, '0');
});

test('Bluetooth stats fill the panel and Summary, with placeholders for missing counts', async () => {
    let stats = { total_devices: 9, ble_count: 6, classic_count: 3, anomaly_count: 2 };
    const f = panel({ routes: url => (url.startsWith('/api/bluetooth/stats') ? stats : undefined) });
    await f.tick(500);
    const shown = () => ['total', 'ble', 'classic', 'anomalies'].map(name => f.el('bt-stat-' + name).textContent);
    assert.deepEqual(shown(), ['9', '6', '3', '2']);
    assert.equal(f.el('sum-bt-devices').textContent, '9');
    stats = { total_devices: 0 };
    await f.tick(20000);
    assert.deepEqual(shown(), ['0', '--', '--', '--']);
    stats = NOT_JSON();
    await f.tick(20000);
    assert.deepEqual(shown(), ['0', '--', '--', '--'], 'a failed refresh keeps the last stats');
});

test('anomaly cards show priority, nodes, dimensions and reasons as text, and say when the queue is empty', async () => {
    let anomalies = { anomalies: [
        { id: 1, device_addr: A1, device_name: MARKUP, device_type: 'ble', anomaly_score: 0.9, rssi_dbm: -50, manufacturer: 'Acme',
            baseline_status: 'drift', seen_count: 3, node_ids: { n1: -70, n2: -40, n3: -90 }, timestamp: T1,
            dimensions: { spoofed_identity: 0.8, [MARKUP]: 0.3, new_device: 0.2, adv_anomaly: 0.1, type_change: 0.05 },
            reasons: ['r1', MARKUP, 'r3', 'r4'] },
        { id: 2, device_addr: A2, device_type: 'classic', anomaly_score: 0.6, node_id: 'n4', seen_count: 1, dimensions: { rogue_device: 0, name_change: 0.4 } },
        { id: 3, device_type: 'dual', anomaly_score: 0.35, node_ids: { n5: -60 } },
        { id: 4, device_type: 'other', anomaly_score: 0.1 },
        { id: 5 }], total: 120 };
    const f = panel({ anomalies: { anomalies: [] }, routes: url => (url.startsWith('/api/bluetooth/anomalies?min_score=0.3') ? anomalies : undefined) });
    await f.tick(1000);
    assert.equal(f.el('bt-anomaly-count-badge').textContent, '5 / 120');
    assert.equal(f.el('sum-bt-anomalies').textContent, '120');
    assert.equal(f.el('bt-anomaly-empty').style.display, 'none');
    const [first, second, third, fourth, fifth] = cards(f);
    assert.deepEqual(cards(f).map(card => card.className.split(' ')[1]),
        ['priority-critical', 'priority-anomalous', 'priority-interesting', 'priority-normal', 'priority-normal']);
    assert.deepEqual(cards(f).map(card => card.querySelector('strong').textContent), [MARKUP, '(unnamed)', '(unnamed)', '(unnamed)', '(unnamed)']);
    assert.deepEqual(cards(f).map(card => (card.querySelector('.anomaly-card-header .admin-badge') || { textContent: null }).textContent),
        ['BLE', 'Classic', 'Dual', 'Unknown', null]);
    assert.equal(first.querySelector('.seen-count').textContent, 'seen 3x');
    assert.ok(!second.querySelector('.seen-count'));
    assert.ok(first.textContent.includes('RSSI: -50.0 dBm') && first.textContent.includes('Manufacturer: Acme') && first.textContent.includes('drift'));
    assert.ok(fifth.textContent.includes('RSSI: --') && fifth.textContent.includes('Manufacturer: --') && fifth.textContent.includes('0.00'));
    // The strongest of several reporting nodes is marked; a single node is shown as is.
    assert.deepEqual(first.querySelectorAll('.node-tag').map(tag => [tag.textContent, tag.classList.contains('node-strongest')]),
        [['n1 (-70.0 dBm)', false], ['n2 (-40.0 dBm)', true], ['n3 (-90.0 dBm)', false]]);
    assert.deepEqual(second.querySelectorAll('.node-tag').map(tag => tag.textContent), ['n4']);
    assert.deepEqual(third.querySelectorAll('.node-tag').map(tag => [tag.textContent, tag.classList.contains('node-strongest')]), [['n5 (-60.0 dBm)', false]]);
    assert.ok(!fourth.querySelector('.anomaly-card-nodes'));
    assert.deepEqual(first.querySelectorAll('.dim-tag').map(tag => tag.textContent),
        ['Spoofed Identity: 0.80', MARKUP + ': 0.30', 'New Device: 0.20', 'Adv Anomaly: 0.10'], 'the top four dimensions');
    assert.deepEqual(second.querySelectorAll('.dim-tag').map(tag => tag.textContent), ['Name Change: 0.40'], 'only active dimensions');
    assert.deepEqual(first.querySelectorAll('.anomaly-reasons small').map(el => el.textContent), ['r1', MARKUP, 'r3']);
    assert.deepEqual(injected(f.el('bt-anomaly-queue')), []);
    assert.deepEqual(btEvents(f), [['critical', MARKUP], ['anomalous', A2]]);

    anomalies = { anomalies: [{ id: 6, anomaly_score: 0.75 }] };
    await f.tick(15000);
    assert.equal(f.el('bt-anomaly-count-badge').textContent, '1', 'a reply without a total counts what it returned');
    assert.equal(btEvents(f).at(-1)[1], 'Unknown BT');
    anomalies = {};
    await f.tick(15000);
    assert.equal(f.el('bt-anomaly-queue').textContent, '');
    assert.equal(f.el('bt-anomaly-empty').style.display, '');
    assert.equal(f.el('bt-anomaly-count-badge').textContent, '0');
    anomalies = NOT_JSON();
    await f.tick(15000);
    assert.ok(f.el('bt-anomaly-queue').textContent.includes('Failed to load Bluetooth anomalies'));
    anomalies = { anomalies: [{ id: 7, anomaly_score: 0.4 }] };
    f.el('bt-anomaly-queue').querySelector('.retry-btn').click();
    await settle();
    assert.equal(cards(f).length, 1);
});

test('a node without an RSSI reading is not marked as the strongest observer', async () => {
    const f = panel({ anomalies: [{ id: 1, anomaly_score: 0.5, node_ids: { n1: -70, n2: -40, n3: null } }] });
    await f.tick(1000);
    const tags = cards(f)[0].querySelectorAll('.node-tag');
    assert.equal(tags[2].textContent, 'n3 (? dBm)');
    assert.deepEqual(tags.filter(tag => tag.classList.contains('node-strongest')).map(tag => tag.textContent), ['n2 (-40.0 dBm)']);
});

test('the threat timeline gets Bluetooth anomalies from a score of 0.5, as critical from 0.7', async () => {
    const addr = i => 'DD:00:00:00:00:0' + i;
    const f = panel({ anomalies: [0.7, 0.69, 0.5, 0.49].map((anomaly_score, i) => ({ id: i + 1, device_addr: addr(i), anomaly_score })) });
    await f.tick(1000);
    assert.equal(cards(f).length, 4);
    assert.deepEqual(btEvents(f), [['critical', addr(0)], ['anomalous', addr(1)], ['anomalous', addr(2)]]);
});

test('Bluetooth anomalies are drawn on the threat timeline in the colour its legend gives Bluetooth', async () => {
    const f = panel({ ids: ['threat-timeline'], subtrees: ['threat-timeline'], activate: false, anomalies: [{ id: 1, anomaly_score: 0.9 }] });
    const canvas = f.el('threat-timeline-canvas');
    canvas.parentElement.clientWidth = 648;
    canvas.height = 48;
    const fills = [];
    const ctx = new Proxy({}, {
        get: (target, key) => (key in target ? target[key] : key === 'fill' ? () => fills.push(target.fillStyle) : () => ({})),
        set: (target, key, value) => { target[key] = value; return true; },
    });
    canvas.getContext = () => ctx;
    f.bt.activate();
    await f.tick(1000);
    const legend = f.el('threat-timeline-legend').querySelectorAll('span').find(span => span.textContent === 'Bluetooth');
    assert.ok(fills.length > 0, 'the anomaly is drawn');
    assert.deepEqual([...new Set(fills)], [legend.querySelector('.tl-swatch').style.background]);
});

test('dismiss and snooze act on the exact anomaly and report failures', async () => {
    let reply = {};
    const f = panel({ anomalies: [{ id: 'bt/7', device_addr: A1, anomaly_score: 0.5 }],
        routes: (url, opts) => (opts.method === 'PUT' ? reply : undefined) });
    await f.tick(1000);
    const polls = () => urls(f, '/api/bluetooth/anomalies?min_score=0.3').length;
    const before = polls();
    cards(f)[0].querySelector('[data-bt-dismiss]').click();
    await settle();
    assert.equal(f.lastWrite().url, '/api/bluetooth/anomalies/bt%2F7/dismiss');
    assert.equal(f.lastWrite().headers['X-CSRF-Token'], 'csrf-abc123');
    assert.equal(f.toasts().at(-1), 'BT anomaly dismissed');
    assert.equal(polls(), before + 1);
    cards(f)[0].querySelector('[data-bt-snooze]').click();
    await settle();
    assert.equal(f.lastWrite().url, '/api/bluetooth/anomalies/bt%2F7/snooze');
    assert.deepEqual(f.body(f.lastWrite()), { hours: 24 });
    assert.equal(f.toasts().at(-1), 'BT anomaly snoozed for 24h');
    reply = NOT_JSON();
    cards(f)[0].querySelector('[data-bt-dismiss]').click();
    await settle();
    assert.equal(f.toasts().at(-1), 'Failed to dismiss anomaly');
    cards(f)[0].querySelector('[data-bt-snooze]').click();
    await settle();
    assert.equal(f.toasts().at(-1), 'Failed to snooze anomaly');
});

test('bulk dismiss and snooze send exactly the selected numeric IDs', async () => {
    let reply = {};
    const anomalies = [{ id: 1, anomaly_score: 0.9 }, { id: 2, anomaly_score: 0.8 }, { anomaly_score: 0.7 }];
    const f = panel({ anomalies, routes: (url, opts) => (opts.method === 'PUT' ? reply : undefined) });
    await f.tick(1000);
    const bar = f.el('bt-bulk-bar'), count = () => f.el('bt-bulk-count').textContent;
    const dismiss = f.el('bt-bulk-dismiss'), snooze = f.el('bt-bulk-snooze');
    assert.equal(bar.style.display, '');
    assert.deepEqual([dismiss.disabled, snooze.disabled], [true, true]);
    const all = f.el('bt-select-all');
    all.checked = true;
    all.dispatchEvent(new f.context.Event('change'));
    assert.equal(count(), '2 selected', 'an anomaly without an ID cannot be selected');
    assert.deepEqual(cards(f).map(card => card.classList.contains('bulk-selected')), [true, true, false]);
    assert.deepEqual([dismiss.disabled, snooze.disabled], [false, false]);
    f.answerConfirm(false);
    dismiss.click();
    assert.equal(f.dialogs.at(-1)[1], 'Dismiss 2 selected BT anomalies?');
    assert.equal(f.writes().length, 0);
    f.answerConfirm(true);
    reply = NOT_JSON();
    dismiss.click();
    await settle();
    assert.equal(f.toasts().at(-1), 'Bulk dismiss failed');
    snooze.click();
    await settle();
    assert.equal(f.toasts().at(-1), 'Bulk snooze failed');
    assert.equal(count(), '2 selected', 'a failed action keeps the selection');
    reply = {};
    snooze.click();
    await settle();
    assert.equal(f.lastWrite().url, '/api/bluetooth/anomalies/bulk/snooze');
    assert.deepEqual(f.body(f.lastWrite()), { ids: [1, 2], hours: 24 });
    assert.equal(f.toasts().at(-1), 'Snoozed 2 BT anomalies for 24h');
    assert.equal(count(), '0 selected');
    const box = cards(f)[1].querySelector('[data-bt-bulk-id]');
    box.checked = true;
    box.dispatchEvent(new f.context.Event('change'));
    assert.equal(count(), '1 selected');
    f.answerConfirm(false);
    const prompts = f.dialogs.length;
    dismiss.click();
    await settle();
    assert.equal(f.dialogs.length, prompts, 'one selected anomaly is dismissed without a prompt');
    assert.equal(f.lastWrite().url, '/api/bluetooth/anomalies/bulk/dismiss');
    assert.deepEqual(f.body(f.lastWrite()), { ids: [2] });
    assert.equal(f.toasts().at(-1), 'Dismissed 1 BT anomalies');
    await settle();
    all.checked = true;
    all.dispatchEvent(new f.context.Event('change'));
    all.checked = false;
    all.dispatchEvent(new f.context.Event('change'));
    assert.equal(count(), '0 selected');
    const fresh = cards(f)[1].querySelector('[data-bt-bulk-id]');
    fresh.checked = true;
    fresh.dispatchEvent(new f.context.Event('change'));
    assert.ok(cards(f)[1].classList.contains('bulk-selected'));
    fresh.checked = false;
    fresh.dispatchEvent(new f.context.Event('change'));
    assert.equal(count(), '0 selected');
    assert.ok(!cards(f)[1].classList.contains('bulk-selected'));
});

test('Select all stays ticked only while every anomaly is selected', async () => {
    const f = panel({ anomalies: [{ id: 1, anomaly_score: 0.9 }, { id: 2, anomaly_score: 0.8 }] });
    await f.tick(1000);
    const all = f.el('bt-select-all');
    const setBox = (box, checked) => { box.checked = checked; box.dispatchEvent(new f.context.Event('change')); };
    setBox(all, true);
    assert.equal(all.checked, true);
    setBox(cards(f)[0].querySelector('[data-bt-bulk-id]'), false);
    assert.deepEqual([all.checked, f.el('bt-bulk-count').textContent], [false, '1 selected'], 'unticking one card unticks Select all');
    setBox(cards(f)[0].querySelector('[data-bt-bulk-id]'), true);
    assert.equal(all.checked, true, 'ticking the last card ticks it again');
    f.el('bt-bulk-snooze').click();
    await settle();
    assert.deepEqual([all.checked, f.el('bt-bulk-count').textContent], [false, '0 selected'], 'a completed action clears the selection');
});

test('a Bluetooth anomaly without an ID gets a disabled box, and Select all ticks once every anomaly with an ID is selected', async () => {
    const f = panel({ anomalies: [{ id: 1, anomaly_score: 0.9 }, { anomaly_score: 0.8, device_addr: A1 }] });
    await f.tick(1000);
    const boxes = cards(f).map(card => card.querySelector('.bulk-checkbox'));
    assert.deepEqual(boxes.map(box => [box.getAttribute('data-bt-bulk-id'), box.hasAttribute('disabled')]), [['1', false], [null, true]]);
    const all = f.el('bt-select-all');
    const box = boxes[0];
    box.checked = true;
    box.dispatchEvent(new f.context.Event('change'));
    assert.deepEqual([all.checked, f.el('bt-bulk-count').textContent], [true, '1 selected']);
    f.answerConfirm(true);
    f.el('bt-bulk-dismiss').click();
    await settle();
    assert.deepEqual(f.body(f.lastWrite()), { ids: [1] });
});

test('the Bluetooth bulk-action bar hides once the last anomaly is gone', async () => {
    const anomalies = [{ id: 1, anomaly_score: 0.9 }, { id: 2, anomaly_score: 0.8 }];
    const f = panel({ anomalies });
    await f.tick(1000);
    const all = f.el('bt-select-all');
    all.checked = true;
    all.dispatchEvent(new f.context.Event('change'));
    anomalies.length = 0;
    f.answerConfirm(true);
    f.el('bt-bulk-dismiss').click();
    await settle();
    assert.equal(f.el('bt-anomaly-empty').style.display, '');
    assert.equal(f.el('bt-bulk-bar').style.display, 'none');
});

test('live Bluetooth frames refresh only an active panel; polling starts once and stops on deactivation', async () => {
    const f = panel({ cookie: '', token: 'tok-' + 'B'.repeat(40) });
    await f.tick(1000);
    const socket = f.sockets.find(s => s.url === 'wss://bridge.test/api/bluetooth/ws/bluetooth');
    assert.ok(socket, 'a held session token opens the Bluetooth socket');
    assert.deepEqual([...socket.protocols], ['bridge-v1', 'tok-' + 'B'.repeat(40)], 'the credential travels as a sub-protocol, not in the URL');
    socket.open();
    const polls = () => ['/api/bluetooth/devices', '/api/bluetooth/stats', '/api/bluetooth/anomalies?'].map(prefix => urls(f, prefix).length);
    const start = polls();
    f.bt.activate();
    assert.deepEqual(polls(), start, 'activating an active panel starts nothing twice');
    for (const frame of ['garbage', 'null', '{"type":"other"}']) assert.doesNotThrow(() => socket.message(frame));
    assert.deepEqual(polls(), start);
    socket.message({ type: 'bt_ingest' });
    assert.deepEqual(polls(), [start[0] + 1, start[1] + 1, start[2]]);
    socket.message({ type: 'bt_anomaly' });
    assert.deepEqual(polls(), [start[0] + 1, start[1] + 1, start[2] + 1]);
    f.bt.deactivate();
    const stopped = polls();
    socket.message({ type: 'bt_ingest' });
    socket.message({ type: 'bt_anomaly' });
    await f.tick(30000);
    // (Summary polls /api/bluetooth/stats on its own 30 s timer.)
    assert.deepEqual([polls()[0], polls()[2]], [stopped[0], stopped[2]], 'an inactive panel neither polls nor follows live frames');
});

test('a cookie session also receives live Bluetooth updates', async () => {
    const f = panel();
    await settle();
    assert.ok(f.sockets.some(s => s.url === 'wss://bridge.test/api/bluetooth/ws/bluetooth'));
});

test('a MAC seen by both the Wi-Fi and Bluetooth panels is badged on the second card', async () => {
    const mac = '02:00:00:00:00:aa';
    const f = panel({ scripts: ['wifi.js'], ids: ['panel-wifi'], subtrees: ['panel-wifi'], anomalies: [{ id: 1, device_addr: mac, anomaly_score: 0.9 }],
        routes: url => (url.startsWith('/api/wifi/anomalies?min_score=0.3') ? { anomalies: [{ id: 2, bssid: mac, ssid: 'x', anomaly_score: 0.9 }] } : undefined) });
    f.db.wifiPanel.activate();
    await f.tick(1500);
    const wifiCard = f.el('wifi-anomaly-queue').querySelector('.anomaly-card');
    assert.ok(wifiCard.querySelector('.entity-link-badge'), 'the Wi-Fi card, rendered after the Bluetooth one, links to it');
});

test('a MAC seen by the Wi-Fi panel first is badged on the Bluetooth card when it next renders', async () => {
    const mac = '02:00:00:00:00:bb';
    const f = panel({ scripts: ['wifi.js'], ids: ['panel-wifi'], subtrees: ['panel-wifi'], anomalies: [{ id: 1, device_addr: mac.toUpperCase(), anomaly_score: 0.9 }],
        routes: url => (url.startsWith('/api/wifi/anomalies?min_score=0.3') ? { anomalies: [{ id: 2, bssid: mac, ssid: 'x', anomaly_score: 0.9 }] } : undefined) });
    f.db.wifiPanel.activate();
    await f.tick(1500);
    assert.ok(!cards(f)[0].querySelector('.entity-link-badge'), 'rendered before the Wi-Fi sighting');
    await f.tick(15000);
    assert.equal(cards(f)[0].querySelector('.entity-link-badge').textContent, 'Also: WiFi', 'the MAC matches in any case');
});

test('a Bluetooth anomaly reaches the threat timeline once across refreshes', async () => {
    const f = panel({ anomalies: [{ id: 1, device_addr: A1, anomaly_score: 0.9 }] });
    await f.tick(1000);
    await f.tick(30000);
    assert.deepEqual(btEvents(f), [['critical', A1]]);
});

test('with no numeric RSSI from any node, no node is marked strongest', async () => {
    const f = panel({ anomalies: [{ id: 1, anomaly_score: 0.5, node_ids: { n1: null, n2: 'weak' } }] });
    await f.tick(1000);
    const tags = cards(f)[0].querySelectorAll('.node-tag');
    assert.deepEqual(tags.map(tag => tag.textContent), ['n1 (? dBm)', 'n2 (? dBm)']);
    assert.equal(tags.filter(tag => tag.classList.contains('node-strongest')).length, 0);
});

test('an empty device table names its qualifier only when there is one', async () => {
    const f = panel({ devices: DEVICES });
    await settle();
    search(f, 'nothing-like-this');
    assert.equal(f.el('bt-device-tbody').textContent, 'No devices match the search');
    change(f, f.el('bt-device-show-select'), 'authorized');
    assert.equal(f.el('bt-device-tbody').textContent, 'No authorized devices');
});
