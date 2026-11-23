/* The shipped dashboard.js Summary tab, booted in the parsed DOM of
 * untrusted_dom.cjs: what an operator sees for empty, partial and failing
 * server data (stat cards, badges, onboarding, freshness, trends, frequency
 * panels, node health, floor plan), driven through the real fetch,
 * WebSocket and timer paths. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { bootDashboard, response, settle } = require('./untrusted_dom.cjs');

const INDEX = fs.readFileSync(path.resolve(__dirname, '../../../src/sigrift/bridge/templates/index.html'), 'utf8');

/* Make the page's Date follow the simulated clock (f.tick), so every
 * Date.now()-based panel is deterministic. `base` is the page time at clock 0. */
function followClock(f, base = Date.now()) {
    const Real = Date, perf = f.context.performance;
    class PageDate extends Real {
        constructor(...args) { if (args.length) super(...args); else super(base + perf.now()); }
        static now() { return base + perf.now(); }
    }
    f.context.Date = PageDate;
    return base;
}
const statusPolls = f => f.requests.filter(call => call.url.startsWith('/api/status?'));
const text = (f, id) => f.el(id).textContent;
const statusSocket = f => f.sockets.find(socket => socket.url.endsWith('/api/nodes/ws/status'));
const alertSocket = f => f.sockets.find(socket => socket.url.endsWith('/api/alerts/ws/alerts'));

/* -- Edge-agent onboarding card --------------------------------------- */

const ONBOARDING = ['edge-onboarding-card', 'edge-onboarding-heading', 'edge-onboarding-sub', 'button:edge-onboarding-dismiss',
    'edge-onboarding-installer', 'edge-onboarding-waiting', 'code:edge-install-oneliner', 'button:edge-oneliner-copy', 'span:edge-oneliner-copied'];
const INSTALL = 'curl -sfL --cacert gateway-cert.pem https://bridge.test/api/edge/install.sh | sudo bash -s -- '
    + '--api-url https://bridge.test --ca-cert gateway-cert.pem --api-key ';
const onboarding = (status, session) => bootDashboard({ ids: ONBOARDING, session, routes: url => url.startsWith('/api/status') ? status : undefined });

test('with no edge agent reporting, the onboarding card shows this dashboard\'s install command until the operator hides it', async () => {
    const f = onboarding({ node_count: 0, active_nodes: 0 });
    const card = f.el('edge-onboarding-card');
    assert.equal(card.style.display, 'none', 'hidden until the first status poll answers');
    await settle();
    assert.equal(card.style.display, 'block');
    assert.equal(text(f, 'edge-install-oneliner'), INSTALL + 'YOUR_NODE_KEY', 'the <bridge-url> placeholders name this origin');
    f.el('edge-onboarding-dismiss').click();
    assert.equal(card.style.display, 'none');
    await f.tick(30000);
    assert.ok(statusPolls(f).length >= 3);
    assert.equal(card.style.display, 'none', 'Hide holds across polls for the rest of the session');
});

test('Hide on the onboarding card lasts across a reload of the same tab', async () => {
    const first = onboarding({ node_count: 0 });
    await settle();
    first.el('edge-onboarding-dismiss').click();
    const left = { 'edge-onboarding-dismissed': first.context.sessionStorage.getItem('edge-onboarding-dismissed') };
    assert.equal(left['edge-onboarding-dismissed'], '1', 'Hide is remembered for the tab');

    const reloaded = onboarding({ node_count: 0 }, left);
    await settle();
    await reloaded.tick(30000);
    assert.ok(statusPolls(reloaded).length >= 2);
    assert.equal(reloaded.el('edge-onboarding-card').style.display, 'none', 'the reloaded tab keeps the card hidden');

    const fresh = onboarding({ node_count: 0 });
    await settle();
    assert.equal(fresh.el('edge-onboarding-card').style.display, 'block', 'a new tab session prompts again');

    const other = onboarding({ node_count: 0 }, { 'edge-onboarding-dismissed': '0' });
    await settle();
    assert.equal(other.el('edge-onboarding-card').style.display, 'block', 'only the value Hide writes counts as hidden');
});

test('Hide still holds for the page when the browser refuses session storage', async () => {
    const f = onboarding({ node_count: 0 });
    const refuse = () => { throw new Error('SecurityError'); };
    f.context.sessionStorage.getItem = refuse;
    f.context.sessionStorage.setItem = refuse;
    await settle();
    const card = f.el('edge-onboarding-card');
    assert.equal(card.style.display, 'block', 'an unreadable store does not hide the card');
    f.el('edge-onboarding-dismiss').click();
    assert.equal(card.style.display, 'none');
    await f.tick(30000);
    assert.equal(card.style.display, 'none');
});

test('Copy command copies the install command with the key placeholder turned into a shell comment', async () => {
    const f = onboarding({ node_count: 0 });
    await settle();
    const copy = f.el('edge-oneliner-copy'), copied = f.el('edge-oneliner-copied');
    const safe = INSTALL + '# REPLACE WITH YOUR KEY';
    const writes = [];
    f.context.navigator.clipboard = { writeText: value => { writes.push(value); return Promise.resolve(); } };
    copy.click();
    await settle();
    assert.ok(writes.includes(safe), JSON.stringify(writes));
    assert.notEqual(copied.style.display, 'none', 'the operator sees "Copied"');
    await f.tick(2000);
    assert.equal(copied.style.display, 'none', 'and it clears itself');

    // A browser that refuses the Clipboard API (plain HTTP, permissions) falls back to a selection copy.
    const selections = [];
    f.document.execCommand = command => {
        const area = f.document.body.querySelector('textarea');
        selections.push([command, area && area.value]);
        return true;
    };
    f.context.navigator.clipboard = { writeText: () => Promise.reject(new Error('denied')) };
    copy.click();
    await settle();
    assert.ok(selections.some(([command, value]) => command === 'copy' && value === safe), JSON.stringify(selections));
    assert.equal(f.document.body.querySelectorAll('textarea').length, 0, 'the temporary text area is removed again');
    assert.notEqual(copied.style.display, 'none');
    await f.tick(2000);

    // No Clipboard API at all: one selection copy, of the safe command.
    selections.length = 0;
    delete f.context.navigator.clipboard;
    copy.click();
    assert.deepEqual(selections, [['copy', safe]]);
    assert.notEqual(copied.style.display, 'none');
});

test('Copy command never puts the literal YOUR_NODE_KEY placeholder on the clipboard', async () => {
    const f = onboarding({ node_count: 0 });
    await settle();
    const writes = [];
    f.context.navigator.clipboard = { writeText: value => { writes.push(value); return Promise.resolve(); } };
    f.el('edge-oneliner-copy').click();
    await settle();
    assert.ok(writes.length > 0);
    for (const value of writes) assert.ok(!value.includes('YOUR_NODE_KEY'), value);
});

test('the onboarding card stays hidden once edge agents report', async () => {
    const f = onboarding({ node_count: 3, active_nodes: 3 });
    await settle();
    assert.equal(f.el('edge-onboarding-card').style.display, 'none');
});

test('a pre-registered in-stack scanner key shows the waiting-for-heartbeat state, not the installer', async () => {
    const f = onboarding({ node_count: 0, local_scanner_key_registered: true });
    await settle();
    assert.equal(f.el('edge-onboarding-waiting').style.display, '');
    assert.equal(f.el('edge-onboarding-installer').style.display, 'none');
    assert.equal(text(f, 'edge-onboarding-heading'), 'In-stack scanners registered, awaiting heartbeat');
});

test('the onboarding card follows each poll: installer, waiting for heartbeat, then hidden once a node reports', async () => {
    let status = { node_count: 0 };
    const f = bootDashboard({ ids: ONBOARDING, routes: url => url.startsWith('/api/status') ? status : undefined });
    await settle();
    const card = f.el('edge-onboarding-card');
    const shown = () => [card.style.display, f.el('edge-onboarding-installer').style.display,
        f.el('edge-onboarding-waiting').style.display, text(f, 'edge-onboarding-heading')];
    assert.deepEqual(shown(), ['block', '', 'none', 'No edge agents are reporting yet']);
    status = { node_count: 0, local_scanner_key_registered: true };
    await f.tick(15000);
    assert.deepEqual(shown(), ['block', 'none', '', 'In-stack scanners registered, awaiting heartbeat']);
    status = { node_count: 1, active_nodes: 1, local_scanner_key_registered: true };
    await f.tick(15000);
    assert.equal(card.style.display, 'none');
    status = { active_nodes: 2 };
    await f.tick(15000);
    assert.equal(card.style.display, 'none', 'a payload that only counts active nodes still hides the card');
});

/* -- Stat cards and tab badges ---------------------------------------- */

test('the Unacked Critical card counts open criticals and the nodes they touch, and keeps its value when the lookup fails', async () => {
    let answer = [{ node_id: 'edge-1' }, { node_id: 'edge-2' }, { node_id: 'edge-1' }, {}];
    const f = bootDashboard({ ids: ['stat-unacked-critical-card', 'stat-unacked-critical', 'stat-unacked-critical-sub'],
        routes: url => url.startsWith('/api/alerts/?severity=critical&acknowledged=false') ? answer : undefined });
    await settle();
    const card = () => [text(f, 'stat-unacked-critical'), text(f, 'stat-unacked-critical-sub'),
        f.el('stat-unacked-critical-card').getAttribute('data-state')];
    const next = async value => { answer = value; await f.tick(15000); return card(); };
    assert.deepEqual(card(), ['4', '4 open — 2 nodes', 'nonzero']);
    assert.deepEqual(await next([{ node_id: 'edge-1' }]), ['1', '1 open — 1 node', 'nonzero']);
    assert.deepEqual(await next([{}, {}]), ['2', '2 open', 'nonzero'], 'criticals without a node name no node count');
    assert.deepEqual(await next(response(503, {})), ['2', '2 open', 'nonzero'], 'a failed lookup does not flap to zero');
    assert.deepEqual(await next({ detail: 'not a list' }), ['0', 'no open criticals', 'zero']);
});

test('missing status counters show placeholders, and tab badges appear with a capped count only while non-zero', async () => {
    let status = {}, metrics = {};
    const f = bootDashboard({
        ids: ['stat-det-rate', 'stat-det-detail', 'stat-anomaly-count', 'stat-anomaly-detail', 'stat-alert-count', 'stat-alert-detail',
            'stat-freq-count', 'stat-freq-detail', 'span:uptime-display', 'tab-badge-rf', 'tab-badge-alerts', 'tab-badge-incidents'],
        routes: url => url.startsWith('/api/status') ? status : url.startsWith('/api/incidents/metrics') ? metrics : undefined });
    await settle();
    const cards = () => ['stat-det-rate', 'stat-det-detail', 'stat-anomaly-count', 'stat-anomaly-detail', 'stat-alert-count',
        'stat-alert-detail', 'stat-freq-count', 'stat-freq-detail', 'uptime-display'].map(id => text(f, id));
    const badge = id => [f.el(id).className, text(f, id)];
    assert.deepEqual(cards(), ['0.0/sec', '0 total (24h)', '--', '0 active', '--', '0 unacked', '--', 'last 1h', 'Uptime: ']);
    for (const id of ['tab-badge-rf', 'tab-badge-alerts', 'tab-badge-incidents']) assert.deepEqual(badge(id), ['tab-badge', ''], id);

    status = { detections_per_second: 2.5, total_detections_24h: 900, active_anomalies: 150, alert_count: 7, unacked_alerts: 3,
        active_frequencies: 12, uptime_seconds: 3725 };
    metrics = { open: 1, investigating: 2 };
    await f.tick(15000);
    assert.deepEqual(cards(), ['2.5/sec', '900 total (24h)', '150', '150 active', '7', '3 unacked', '12', 'last 1h', 'Uptime: 1h 2m']);
    assert.deepEqual(badge('tab-badge-rf'), ['tab-badge badge-visible badge-warning', '99+']);
    assert.deepEqual(badge('tab-badge-alerts'), ['tab-badge badge-visible badge-critical', '3']);
    assert.deepEqual(badge('tab-badge-incidents'), ['tab-badge badge-visible badge-warning', '3']);

    // Counters back at zero show 0, not a placeholder, and clear the badges; a negative uptime is not shown.
    status = { detections_per_second: 0, total_detections_24h: 0, active_anomalies: 0, alert_count: 0, unacked_alerts: 0,
        active_frequencies: 0, uptime_seconds: -5 };
    metrics = { open: 0 };
    await f.tick(15000);
    assert.deepEqual(cards(), ['0.0/sec', '0 total (24h)', '0', '0 active', '0', '0 unacked', '0', 'last 1h', 'Uptime: ']);
    for (const id of ['tab-badge-rf', 'tab-badge-alerts', 'tab-badge-incidents']) assert.deepEqual(badge(id), ['tab-badge', ''], id);
});

const FREQ_RANGE = /<div class="det-time-range" id="active-freqs-range"[^>]*>([\s\S]*?)<\/div>/.exec(INDEX)[1];

test('the active-frequency window buttons re-query status for that window and label it', async () => {
    const f = bootDashboard({ ids: ['stat-freq-detail', 'active-freqs-range'] });
    await settle();
    // The page's own window buttons; the stub DOM adds them after boot, so they are wired as the constructor wires them.
    f.el('active-freqs-range').innerHTML = FREQ_RANGE;
    f.db._initFreqRange();
    const buttons = f.el('active-freqs-range').querySelectorAll('button');
    assert.deepEqual(buttons.map(button => button.textContent), ['1h', '4h', '24h', '7d']);
    const pick = async caption => {
        const button = buttons.find(candidate => candidate.textContent === caption);
        button.click();
        await settle();
        return [statusPolls(f).at(-1).url.replace(/&_t=\d+$/, ''), text(f, 'stat-freq-detail'),
            buttons.filter(candidate => candidate.classList.contains('active')).length, button.classList.contains('active')];
    };
    assert.deepEqual(await pick('24h'), ['/api/status?freq_hours=24', 'last 24h', 1, true]);
    assert.deepEqual(await pick('7d'), ['/api/status?freq_hours=168', 'last 7d', 1, true]);
    assert.deepEqual(await pick('4h'), ['/api/status?freq_hours=4', 'last 4h', 1, true]);
    assert.deepEqual(await pick('1h'), ['/api/status?freq_hours=1', 'last 1h', 1, true]);
});

test('Bluetooth and Zigbee summary counts show placeholders for missing fields and keep the last value on failure', async () => {
    let bluetooth = {}, zigbee = { pan_ids: ['0x1a2b', '0x3c4d', '0x5e6f'] };
    const f = bootDashboard({ ids: ['sum-bt-devices', 'sum-bt-anomalies', 'sum-zb-devices', 'sum-zb-pan-ids', 'tab-badge-bluetooth'],
        routes: url => url.startsWith('/api/bluetooth/stats') ? bluetooth : url.startsWith('/api/zigbee/stats') ? zigbee : undefined });
    await settle();
    const counts = () => ['sum-bt-devices', 'sum-bt-anomalies', 'sum-zb-devices', 'sum-zb-pan-ids'].map(id => text(f, id));
    assert.deepEqual(counts(), ['--', '--', '0', '3'], 'a PAN ID list counts its entries');
    assert.equal(f.el('tab-badge-bluetooth').className, 'tab-badge');
    bluetooth = { total_devices: 5, anomaly_count: 2 };
    zigbee = { total_devices: 4, pan_ids: 2 };
    await f.tick(30000);
    assert.deepEqual(counts(), ['5', '2', '4', '2'], 'a PAN ID count is shown as is');
    assert.deepEqual([f.el('tab-badge-bluetooth').className, text(f, 'tab-badge-bluetooth')], ['tab-badge badge-visible badge-warning', '2']);
    bluetooth = response(503, {});
    zigbee = new Error('offline');
    await f.tick(30000);
    assert.deepEqual(counts(), ['5', '2', '4', '2']);
});

/* -- Per-source freshness and stale data ------------------------------ */

/* index.html's own summary groups and labels, with the help buttons
 * panel_help.js adds to them on the page. */
const GROUP_IDS = { system: 'summary-general', sdr: 'summary-sdr', wifi: 'summary-wifi', bluetooth: 'summary-bluetooth', zigbee: 'summary-zigbee' };
const freshness = routes => bootDashboard({ ids: Object.values(GROUP_IDS), routes });
function summaryGroups(f) {
    const groups = {};
    for (const [source, id] of Object.entries(GROUP_IDS)) {
        const label = new RegExp(`id="${id}"[^>]*>\\s*(<div class="summary-group-label"[^>]*>[^<]*</div>)`).exec(INDEX)[1];
        groups[source] = f.el(id);
        // Re-indented as a formatter would wrap it: the lookup must not depend on whitespace around the label.
        groups[source].innerHTML = label.replace(/>([^<]*)</, '>\n                        $1\n                    <') + '<div class="stat-card"></div>';
    }
    f.load('panel_help.js');
    assert.ok(groups.wifi.querySelector('.summary-group-label .panel-help-button'), 'the Wi-Fi label carries its help button');
    return groups;
}
const stale = group => [group.classList.contains('freshness-stale'), group.getAttribute('data-freshness-stale'), group.getAttribute('title')];

test('a summary group turns stale when its source has not answered for two poll cycles, and clears when it recovers', async () => {
    let wifiUp = true;
    const f = freshness(url => url.startsWith('/api/wifi/stats') ? (wifiUp ? { total_networks: 1 } : response(503, {})) : undefined);
    followClock(f);
    const groups = summaryGroups(f);
    await settle();
    wifiUp = false;
    await f.tick(60000);
    assert.deepEqual(stale(groups.wifi), [false, null, null], 'exactly two missed cycles are tolerated');
    await f.tick(5000);
    assert.deepEqual(stale(groups.wifi), [true, 'true',
        'Wi-Fi data stale (no successful fetch in 65s; backend scanner may be down)']);
    assert.equal(groups.wifi.style.borderLeft, '4px solid var(--accent-red, #e5534b)');
    for (const source of ['system', 'sdr', 'bluetooth', 'zigbee']) assert.deepEqual(stale(groups[source]), [false, null, null], source);
    wifiUp = true;
    await f.tick(25000);
    assert.deepEqual(stale(groups.wifi), [false, null, null]);
    assert.equal(groups.wifi.style.borderLeft, '');
});

test('a source that never answers marks its summary group stale', async () => {
    const f = freshness(url => url.startsWith('/api/wifi/stats') ? response(503, {}) : undefined);
    followClock(f);
    const groups = summaryGroups(f);
    await settle();
    await f.tick(120000);
    assert.equal(stale(groups.wifi)[0], true);
});

test('a source down from page load is tolerated for two poll cycles, like one that stops answering', async () => {
    const f = freshness(url => url.startsWith('/api/bluetooth/stats') ? response(503, {}) : undefined);
    followClock(f);
    const groups = summaryGroups(f);
    await settle();
    await f.tick(60000);
    assert.deepEqual(stale(groups.bluetooth), [false, null, null], 'no red flash while the first cycles run');
    await f.tick(5000);
    assert.deepEqual(stale(groups.bluetooth), [true, 'true',
        'Bluetooth SIGINT data stale (no successful fetch in 65s; backend scanner may be down)']);
    for (const source of ['system', 'sdr', 'wifi', 'zigbee']) assert.deepEqual(stale(groups[source]), [false, null, null], source);
});

test('the stale-data notice appears after 30 s without fresh data and clears on the next good status', async () => {
    let up = false;
    const f = bootDashboard({ ids: ['span:stale-data-ago'], routes: url => url.startsWith('/api/status') ? (up ? {} : response(503, {})) : undefined });
    followClock(f);
    statusSocket(f).open();  // a (re)connect marks the data fresh at clock 0
    await settle();
    const body = f.document.body;
    await f.tick(30000);
    assert.equal(body.classList.contains('data-stale'), false);
    await f.tick(5000);
    assert.equal(body.classList.contains('data-stale'), true);
    assert.equal(text(f, 'stale-data-ago'), '35');
    up = true;
    await f.tick(10000);     // the 45 s status poll succeeds
    assert.equal(body.classList.contains('data-stale'), false);
});

test('summary stats show a trend arrow and sparkline once three polls have been seen', async () => {
    const rates = [1, 1, 2, 0.5];
    let poll = 0;
    const ids = ['stat-det-rate', 'stat-anomaly-count', 'stat-alert-count'];
    const f = bootDashboard({ ids, routes: url => {
        if (!url.startsWith('/api/status')) return undefined;
        const rate = rates[Math.min(poll++, rates.length - 1)];
        return { detections_per_second: rate, active_anomalies: 5, alert_count: 0 };
    } });
    // Each stat sits in its own card, as on the page.
    for (const id of ids) {
        const card = f.document.createElement('div');
        f.document.body.appendChild(card);
        card.appendChild(f.el(id));
    }
    await settle();
    const trend = id => f.el(id).parentElement.querySelector('.stat-trend');
    const trends = id => f.el(id).parentElement.querySelectorAll('.stat-trend').length;
    const shown = id => [trend(id).className, trend(id).textContent.trim(), trend(id).querySelector('polyline').getAttribute('stroke')];
    assert.equal(trends('stat-det-rate'), 0, 'a single sample is not a trend');
    await f.tick(15000);
    assert.equal(trends('stat-det-rate'), 0);
    await f.tick(15000);
    assert.deepEqual(shown('stat-det-rate'), ['stat-trend trend-up', '↑ 100%', 'var(--accent-red)']);
    // The sparkline follows the samples 1, 1, 2 from left to right: level, then up (SVG y grows downwards).
    const points = trend('stat-det-rate').querySelector('polyline').getAttribute('points').trim().split(/\s+/)
        .map(point => point.split(',').map(Number));
    assert.equal(points.length, 3);
    assert.ok(points[0][0] < points[1][0] && points[1][0] < points[2][0], JSON.stringify(points));
    assert.ok(points[0][1] === points[1][1] && points[2][1] < points[1][1], JSON.stringify(points));
    assert.deepEqual(shown('stat-anomaly-count'), ['stat-trend trend-flat', '→', 'var(--text-secondary)'], 'a steady count is flat');
    assert.deepEqual(shown('stat-alert-count'), ['stat-trend trend-flat', '→', 'var(--text-secondary)'], 'all zeros is flat, not NaN');
    await f.tick(15000);
    assert.deepEqual(shown('stat-det-rate'), ['stat-trend trend-down', '↓ 63%', 'var(--accent-green)']);
    assert.equal(f.document.body.querySelectorAll('.stat-trend').length, 3, 'each card keeps exactly one indicator');
});

/* -- Frequency panels -------------------------------------------------- */

const BANDS = [[100.1, 'FM Broadcast'], [121.5, 'Airband'], [146.5, '2m Amateur'], [155, 'VHF'], [300, 'UHF Mil'],
    [433.9, '70cm / ISM 433'], [462.6, 'FRS/GMRS'], [600, 'UHF TV'], [750, 'LTE'], [868.3, 'ISM 868'], [915, 'ISM 915'],
    [1176.5, 'GPS L5'], [1227.6, 'GPS L2'], [1575.4, 'GPS L1'], [1900, 'LTE/AWS'], [2437, 'ISM 2.4G / WiFi'],
    [5800, 'WiFi 5G'], [6500, 'WiFi 6E'], [9000, 'Other']];

test('each active frequency is labelled with its band', async () => {
    const list = BANDS.map(([mhz]) => ({ freq_mhz: mhz, count: 5, classes: 'fm', nodes: 'a,b', avg_power_dbm: -50 }));
    const f = bootDashboard({ ids: ['tbody:active-freqs-tbody'], routes: url => url.startsWith('/api/status') ? { active_frequency_list: list } : undefined });
    await settle();
    const rows = f.el('active-freqs-tbody').querySelectorAll('tr');
    assert.deepEqual(rows.map(row => [Number(row.querySelector('td').textContent), row.querySelectorAll('td')[1].textContent]), BANDS);
});

test('NOAA weather radio frequencies are labelled as NOAA Weather', async () => {
    const f = bootDashboard({ ids: ['tbody:active-freqs-tbody'], routes: url => url.startsWith('/api/status')
        ? { active_frequency_list: [{ freq_mhz: 162.55, count: 5, classes: 'fm', nodes: 'a', avg_power_dbm: -50 }] } : undefined });
    await settle();
    assert.equal(f.el('active-freqs-tbody').querySelectorAll('td')[1].textContent, 'NOAA Weather');
});

test('the NOAA Weather band covers 162.4-162.6 MHz and the rest of 150-174 MHz stays VHF', async () => {
    const bands = [[150, 'VHF'], [162.3, 'VHF'], [162.4, 'NOAA Weather'], [162.475, 'NOAA Weather'], [162.6, 'NOAA Weather'],
        [162.7, 'VHF'], [174, 'VHF']];
    const list = bands.map(([mhz]) => ({ freq_mhz: mhz, count: 5, classes: 'fm', nodes: 'a', avg_power_dbm: -50 }));
    const f = bootDashboard({ ids: ['tbody:active-freqs-tbody'], routes: url => url.startsWith('/api/status') ? { active_frequency_list: list } : undefined });
    await settle();
    const rows = f.el('active-freqs-tbody').querySelectorAll('tr');
    assert.deepEqual(rows.map(row => [Number(row.querySelector('td').textContent), row.querySelectorAll('td')[1].textContent]), bands);
});

test('unique frequencies group by band, busiest band first, with a capped frequency list', async () => {
    const fm = [88.5, 89.5, 90.5, 91.5, 92.5, 93.5].map((mhz, i) => ({ freq_mhz: mhz, count: 10, avg_power_dbm: i < 2 ? null : -40 - i }));
    let list = [{ freq_mhz: 121.5, count: 3, avg_power_dbm: null }, ...fm];
    const f = bootDashboard({ ids: ['unique-freqs-grid', 'span:unique-freqs-badge', 'p:unique-freqs-empty'],
        routes: url => url.startsWith('/api/status') ? { active_frequency_list: list } : undefined });
    await settle();
    const grid = f.el('unique-freqs-grid');
    const cards = () => grid.querySelectorAll('.freq-band-card').map(card => ['.freq-band-name', '.freq-band-value', '.freq-band-stats', '.freq-band-freqs']
        .map(selector => card.querySelector(selector).textContent));
    assert.deepEqual(cards(), [
        ['FM Broadcast', '6 freqs', '60 det-43.5 dBm', '88.5, 89.5, 90.5, 91.5, 92.5 +1 more MHz'],
        ['Airband', '1 freq', '3 det--', '121.5 MHz']]);
    assert.equal(grid.querySelector('.freq-band-freqs').getAttribute('title'), fm.map(row => row.freq_mhz).join(', '), 'the full list stays on hover');
    assert.equal(text(f, 'unique-freqs-badge'), '2 bands');
    assert.equal(f.el('unique-freqs-empty').style.display, 'none');
    list = fm.slice(0, 1);
    await f.tick(15000);
    assert.equal(text(f, 'unique-freqs-badge'), '1 band');
    list = [];
    await f.tick(15000);
    assert.deepEqual([grid.children.length, text(f, 'unique-freqs-badge'), f.el('unique-freqs-empty').style.display], [0, '0 bands', '']);
});

test('suspicious frequencies rank power outliers above single-node sightings and clear when nothing stands out', async () => {
    const steady = [100.1, 100.3, 100.5, 100.7, 100.9, 101.1, 101.3, 101.5, 101.7, 101.9]
        .map(mhz => ({ freq_mhz: mhz, count: 40, nodes: 'a,b', avg_power_dbm: -60 }));
    let list = [...steady, { freq_mhz: 104.1, count: 40, nodes: 'a', avg_power_dbm: null },
        { freq_mhz: 433.9, count: 2, nodes: 'a,b', avg_power_dbm: -10 }];
    const f = bootDashboard({ ids: ['suspicious-freqs-list', 'span:suspicious-freqs-badge', 'p:suspicious-freqs-empty'],
        routes: url => url.startsWith('/api/status') ? { active_frequency_list: list } : undefined });
    await settle();
    const panel = f.el('suspicious-freqs-list');
    const items = () => panel.querySelectorAll('.suspicious-freq-item').map(item => [item.className,
        item.querySelector('.suspicious-freq-title').textContent,
        item.querySelectorAll('.suspicious-freq-reason').map(reason => reason.textContent),
        item.querySelectorAll('.suspicious-freq-meta span').map(span => span.textContent)]);
    // Ranking between severities is pinned by the BUG test below.
    assert.deepEqual(items().sort((a, b) => a[1].localeCompare(b[1])), [
        ['suspicious-freq-item severity-low', '104.1 MHz — FM Broadcast', ['Single-node sighting (a)'], ['40 det', '--', '1 node']],
        ['suspicious-freq-item severity-high', '433.9 MHz — 70cm / ISM 433',
            ['Power outlier: -10.0 dBm (avg -55.5)', 'Transient signal: only 2 detections'], ['2 det', '-10.0 dBm', '2 nodes']]]);
    assert.equal(text(f, 'suspicious-freqs-badge'), '2');
    assert.equal(f.el('suspicious-freqs-empty').style.display, 'none');
    list = steady.slice(0, 2);
    await f.tick(15000);
    assert.deepEqual([panel.children.length, text(f, 'suspicious-freqs-badge'), f.el('suspicious-freqs-empty').style.display], [0, '0', '']);
});

test('a power outlier is a frequency more than 1.5 standard deviations above the mean power', async () => {
    // An even ladder of powers, -80 to -60 dBm: the top rung sits 1.65 sigma above the mean, the next one 1.49 sigma.
    const list = Array.from({ length: 21 }, (_, i) => ({ freq_mhz: Number((88.1 + i * 0.5).toFixed(1)), count: 40, nodes: 'a,b', avg_power_dbm: -80 + i }));
    const f = bootDashboard({ ids: ['suspicious-freqs-list', 'span:suspicious-freqs-badge'],
        routes: url => url.startsWith('/api/status') ? { active_frequency_list: list } : undefined });
    await settle();
    const items = f.el('suspicious-freqs-list').querySelectorAll('.suspicious-freq-item');
    assert.deepEqual(items.map(item => [item.querySelector('.suspicious-freq-title').textContent,
        item.querySelectorAll('.suspicious-freq-reason').map(reason => reason.textContent)]),
    [['98.1 MHz — FM Broadcast', ['Power outlier: -60.0 dBm (avg -70.0)']]]);
    assert.equal(text(f, 'suspicious-freqs-badge'), '1');
});

test('high-severity suspicious frequencies are listed first', async () => {
    const steady = [100.1, 100.3, 100.5, 100.7, 100.9, 101.1].map(mhz => ({ freq_mhz: mhz, count: 40, nodes: 'a,b', avg_power_dbm: -60 }));
    const list = [...steady, { freq_mhz: 300, count: 40, nodes: 'a,b', avg_power_dbm: -60 }, { freq_mhz: 433.9, count: 40, nodes: 'a,b', avg_power_dbm: -5 }];
    const f = bootDashboard({ ids: ['suspicious-freqs-list'], routes: url => url.startsWith('/api/status') ? { active_frequency_list: list } : undefined });
    await settle();
    assert.deepEqual(f.el('suspicious-freqs-list').querySelectorAll('.suspicious-freq-item').map(item => item.className),
        ['suspicious-freq-item severity-high', 'suspicious-freq-item ']);
});

test('suspicious frequencies are ordered high, then medium, then low, whatever order the server sends', async () => {
    const steady = [100.1, 100.3, 100.5, 100.7, 100.9, 101.1].map(mhz => ({ freq_mhz: mhz, count: 40, nodes: 'a,b', avg_power_dbm: -60 }));
    const list = [{ freq_mhz: 104.1, count: 40, nodes: 'a', avg_power_dbm: -60 }, { freq_mhz: 300, count: 40, nodes: 'a,b', avg_power_dbm: -60 },
        ...steady, { freq_mhz: 433.9, count: 40, nodes: 'a,b', avg_power_dbm: -5 }];
    const f = bootDashboard({ ids: ['suspicious-freqs-list'], routes: url => url.startsWith('/api/status') ? { active_frequency_list: list } : undefined });
    await settle();
    assert.deepEqual(f.el('suspicious-freqs-list').querySelectorAll('.suspicious-freq-item').map(item => [item.className,
        item.querySelector('.suspicious-freq-title').textContent]), [
        ['suspicious-freq-item severity-high', '433.9 MHz — 70cm / ISM 433'],
        ['suspicious-freq-item ', '300 MHz — UHF Mil'],
        ['suspicious-freq-item severity-low', '104.1 MHz — FM Broadcast']]);
});

test('active-frequency links drill down to exactly the clicked frequency or signal class', async () => {
    const f = bootDashboard({ ids: ['tbody:active-freqs-tbody'], routes: url => url.startsWith('/api/status')
        ? { active_frequency_list: [{ freq_mhz: 433.9, count: 3, classes: 'lora,fm', nodes: '', avg_power_dbm: null }] } : undefined });
    await settle();
    const row = f.el('active-freqs-tbody').querySelector('tr');
    assert.deepEqual(row.querySelectorAll('td').map(cell => cell.textContent.trim()), ['433.9', '70cm / ISM 433', 'lora fm', '3', '--', '--']);
    const calls = [], rowClicks = [];
    row.addEventListener('click', () => rowClicks.push('row'));
    f.context.drillDown = { toSpectrum: hz => calls.push(['spectrum', hz]), toSignalClass: name => calls.push(['class', name]) };
    row.querySelector('[data-drilldown-summary-freq]').click();
    row.querySelectorAll('[data-drilldown-summary-class]')[1].click();
    assert.deepEqual(calls, [['spectrum', 433900000], ['class', 'fm']]);
    assert.deepEqual(rowClicks, [], 'the link click does not also act on the row');
});

/* -- Node table and floor plan ----------------------------------------- */

/* A node-table cell by its index.html column heading. */
const NODE_COLUMNS = /<table class="data-table" id="nodes-table">[\s\S]*?<thead>([\s\S]*?)<\/thead>/.exec(INDEX)[1]
    .match(/<th[^>]*>[^<]*<\/th>/g).map(th => th.replace(/<[^>]*>/g, '').trim());
const nodeCell = (row, column) => row.querySelectorAll('td')[NODE_COLUMNS.indexOf(column)];

test('node health and top issue name the worst resource problem each node reports', async () => {
    const nodes = [
        { node_id: 'n-cpu', host: 'h', status: 'active', cpu_percent: 80, capabilities: {} },
        { node_id: 'n-cpu-max', host: 'h', status: 'active', cpu_percent: 95, capabilities: {} },
        { node_id: 'n-cpu-90', host: 'h', status: 'active', cpu_percent: 90, capabilities: {} },
        { node_id: 'n-temp', host: 'h', status: 'active', capabilities: { cpu_temp: 75 } },
        { node_id: 'n-lag', host: 'h', status: 'active', capabilities: { heartbeat_latency_ms: 650 } },
        { node_id: 'n-slow', host: 'h', status: 'active', capabilities: { heartbeat_latency_ms: 250 } },
        { node_id: 'n-hot', host: 'h', status: 'active', capabilities: { cpu_temp: 85 } },
        { node_id: 'n-stale', host: 'h', status: 'stale', capabilities: { agent_version: '2.1' } },
        { node_id: 'n-off', host: 'h', status: 'offline', capabilities: { agent_version: '2.1' } },
        { node_id: 'n-busy', host: 'h', status: 'active', capabilities: { capture_mode: 'hackrf', hardware: 'HackRF One', uptime_seconds: 7260 },
            detection_summary: { total_detections: 30, period_seconds: 60, class_counts: { fm: 9, lora: 7, ook: 5, fsk: 3, am: 1 } } },
        { node_id: 'n-rate', host: 'h', status: 'active', classifications_per_sec: 0.25 }];
    const f = bootDashboard({ ids: ['tbody:nodes-tbody'], routes: url => url.startsWith('/api/nodes/?') ? nodes : undefined });
    await settle();
    const row = id => f.el('nodes-tbody').querySelector(`[data-cmd-node="${id}"]`).closest('tr');
    const health = id => [row(id).querySelector('.node-health').getAttribute('title'), row(id).querySelector('.node-top-issue').textContent];
    assert.deepEqual(health('n-cpu'), ['Degraded', '⚠CPU 80%']);
    assert.deepEqual(health('n-cpu-max'), ['Critical', '⚠CPU 95%']);
    assert.deepEqual(health('n-cpu-90'), ['Degraded', '⚠CPU 90%'], 'Critical starts above 90%');
    assert.deepEqual(health('n-temp'), ['Degraded', '⚠Temp 75°C']);
    assert.deepEqual(health('n-lag'), ['Degraded', '⚠Latency 650ms']);
    assert.deepEqual(health('n-slow'), ['Online', 'No issues reported']);
    assert.deepEqual(health('n-hot'), ['Critical', '⚠Temp 85°C']);
    assert.deepEqual(health('n-stale'), ['Stale', '⚠stale']);
    assert.deepEqual(health('n-off'), ['Offline', '⚠offline']);
    assert.ok(nodeCell(row('n-lag'), 'Latency').classList.contains('node-latency-high'));
    assert.deepEqual([nodeCell(row('n-slow'), 'Latency').className, nodeCell(row('n-slow'), 'Latency').textContent],
        ['node-col-detail node-latency-med', '250ms']);
    assert.deepEqual(['n-stale', 'n-off', 'n-cpu'].map(id => row(id).querySelector('.monitor-badge').className),
        ['monitor-badge mon-stale', 'monitor-badge mon-offline', 'monitor-badge mon-none']);
    const busy = row('n-busy');
    assert.equal(busy.querySelector('.node-class-more').textContent, '+2 more');
    assert.deepEqual(busy.querySelectorAll('.node-class-bar').map(bar => bar.getAttribute('title')), ['fm: 9', 'lora: 7', 'ook: 5']);
    assert.equal(busy.querySelector('.capture-badge.hackrf').textContent, 'HackRF');
    assert.ok(busy.textContent.includes('2h 1m'));
    assert.equal(nodeCell(busy, 'Det/min').textContent, '30.0', 'detections per minute from the node summary');
    assert.equal(nodeCell(row('n-rate'), 'Det/min').textContent, '15.0', 'or from its classification rate');
    // A node the Wi-Fi panel reports as monitoring gets a Wi-Fi badge on the next refresh.
    assert.equal(row('n-slow').querySelectorAll('.capture-badge.wifi').length, 0);
    f.db.wifiNodeIds = ['n-slow'];
    await f.tick(10000);
    assert.equal(row('n-slow').querySelector('.capture-badge.wifi').textContent, 'WiFi');
});

function canvasRecorder(canvas) {
    const calls = [];
    const ctx = new Proxy({}, {
        get: (target, key) => (key in target ? target[key] : (...args) => { calls.push([key, ...args, target.fillStyle]); return { addColorStop() {} }; }),
        set: (target, key, value) => { target[key] = value; return true; },
    });
    canvas.getContext = () => ctx;
    return {
        labels: () => calls.filter(call => call[0] === 'fillText' && typeof call[1] === 'string').map(call => [call[1], call.at(-1)]),
        fills: () => calls.filter(call => call[0] === 'fill').map(call => call.at(-1)),
        reset: () => { calls.length = 0; },
    };
}

test('the floor plan draws placed nodes by state, opens a node on click and hides the tooltip off a node', async () => {
    let nodes = [{ node_id: 'edge-active', host: 'h1', status: 'active', position_x: 50, position_y: 50 },
        { node_id: 'edge-offline-long-name', host: 'h2', status: 'offline', position_x: 10, position_y: 10 },
        { node_id: 'unplaced', host: 'h3', status: 'active' }];
    const f = bootDashboard({ ids: ['tbody:nodes-tbody', 'canvas:floorplan-canvas', 'floorplan-tooltip', 'span:floorplan-badge'],
        routes: url => url.startsWith('/api/nodes/?') ? nodes : undefined });
    const canvas = f.el('floorplan-canvas'), draw = canvasRecorder(canvas);
    await settle();
    assert.deepEqual(draw.labels().filter(([label]) => label.startsWith('edge')), [['edge-active', '#c9d1d9'], ['edge-offline..', '#c9d1d9']]);
    assert.ok(draw.fills().includes('#8b949e'), 'an offline node is drawn grey');
    assert.equal(text(f, 'floorplan-badge'), '2 placed');

    const opened = [];
    const at = (type, x, y) => canvas.dispatchEvent(new f.context.Event(type, { clientX: x, clientY: y }));
    at('click', 150, 75);            // no comparison view loaded: nothing to open, nothing thrown
    f.db.nodeComparison = { openForNode: id => opened.push(id) };
    at('click', 150, 75);
    at('click', 54, 39);
    at('click', 100, 100);           // empty floor
    assert.deepEqual(opened, ['edge-active', 'edge-offline-long-name']);
    const tooltip = f.el('floorplan-tooltip');
    at('mousemove', 150, 75);
    assert.deepEqual([tooltip.style.display, canvas.style.cursor], ['', 'pointer']);
    at('mousemove', 100, 100);
    assert.deepEqual([tooltip.style.display, canvas.style.cursor], ['none', 'default']);
    at('mousemove', 150, 75);
    at('mouseleave', 0, 0);
    assert.deepEqual([tooltip.style.display, canvas.style.cursor], ['none', 'default']);

    // Labels follow the page theme; an unknown theme falls back to the dark palette.
    for (const [theme, color] of [['light', '#24292f'], ['neon', '#c9d1d9']]) {
        f.document.documentElement.setAttribute('data-theme', theme);
        draw.reset();
        await f.tick(10000);
        assert.deepEqual(draw.labels().find(([label]) => label === 'edge-active'), ['edge-active', color], theme);
    }
    nodes = [{ node_id: 'unplaced', host: 'h3', status: 'active' }];
    draw.reset();
    await f.tick(10000);
    assert.ok(draw.labels().some(([label]) => label === 'No nodes placed yet. Set positions in Admin > Nodes.'));
    assert.equal(text(f, 'floorplan-badge'), '0 placed');
});

/* -- Summary alerts and activity --------------------------------------- */

test('Summary alerts filter by severity, show slow acknowledgements in hours and report a failed escalation', async () => {
    const t0 = Date.now() - 3 * 3600000;
    let escalate = 500;
    const list = [
        { alert_id: 'a-1', message: 'no severity given', acknowledged: false, escalated: true, triggered_at: new Date(t0).toISOString() },
        { alert_id: 'a-2', severity: 'critical', message: 'acked late', acknowledged: true, acknowledged_by: 'op',
            triggered_at: new Date(t0).toISOString(), acknowledged_at: new Date(t0 + 2 * 3600000).toISOString() }];
    const f = bootDashboard({ ids: ['alerts-list', 'p:alerts-empty', 'span:alert-count-badge', 'select:alert-severity-filter', 'input:alert-hide-acked'],
        scripts: ['severity.js'], routes: (url, options) => {
            if (/^\/api\/alerts\/\?(severity=critical&)?_t=/.test(url)) return list;
            if (options.method === 'PUT') return response(escalate, {});
            return undefined;
        } });
    await settle();
    const items = f.el('alerts-list').querySelectorAll('.alert-item');
    assert.deepEqual(items.map(item => item.className), ['alert-item warning escalated', 'alert-item critical acknowledged']);
    assert.match(items[0].querySelector('.severity-badge').textContent, /warning$/, 'an alert without a severity is shown as a warning');
    assert.equal(items[1].querySelector('.ack-tta').textContent, '(TTA: 2.0h)');

    const filter = f.el('alert-severity-filter');
    filter.value = 'critical';
    filter.dispatchEvent(new f.context.Event('change'));
    await settle();
    assert.match(f.requests.filter(call => call.url.startsWith('/api/alerts/?') && !call.url.includes('limit=')).at(-1).url,
        /^\/api\/alerts\/\?severity=critical&_t=\d+$/);

    f.el('alerts-list').querySelector('[data-escalate-alert="a-1"]').click();
    await settle();
    assert.deepEqual([f.lastWrite().method, f.lastWrite().url, f.body(f.lastWrite())],
        ['PUT', '/api/alerts/a-1/ack', { note: 'ESCALATED', escalated: true }], 'the escalation names exactly that alert');
    assert.ok(f.toasts().includes('Failed to escalate alert'));
    escalate = 200;
    f.el('alerts-list').querySelector('[data-escalate-alert="a-1"]').click();
    await settle();
    assert.ok(f.toasts().includes('Alert escalated'));

    // Hiding acknowledged alerts when every alert is acknowledged shows the empty state.
    list.splice(0, 1);
    const hide = f.el('alert-hide-acked');
    hide.checked = true;
    hide.dispatchEvent(new f.context.Event('change'));
    await settle();
    assert.deepEqual([f.el('alerts-list').children.length, text(f, 'alert-count-badge'), f.el('alerts-empty').style.display], [0, '0', '']);
});

test('the activity log names no node for node-less events and scrolls to the newest entry', async () => {
    const f = bootDashboard({ ids: ['tbody:activity-log', 'p:activity-empty', 'activity-log-wrapper'], routes: url => url.startsWith('/api/nodes/activity')
        ? [{ timestamp: new Date().toISOString(), event_type: 'startup', message: 'bridge started' }] : undefined });
    f.el('activity-log-wrapper').scrollHeight = 480;
    await settle();
    const cells = f.el('activity-log').querySelectorAll('td');
    assert.deepEqual(cells.slice(1).map(cell => cell.textContent), ['', 'startup', 'bridge started']);
    assert.equal(f.el('activity-log-wrapper').scrollTop, 480);
    assert.equal(f.el('activity-empty').style.display, 'none');
});

/* -- Toasts, rate limits and the live connection ------------------------ */

test('rate-limited polls (429) never raise a connection toast; toasts are capped and fade out', async () => {
    const f = bootDashboard({ routes: url => url.startsWith('/api/status') ? response(429, { detail: 'Rate limit exceeded' }) : undefined });
    await settle();
    await f.tick(60000);
    assert.ok(statusPolls(f).length >= 4);
    assert.deepEqual(f.toasts().filter(message => /Connection issue/.test(message)), []);

    const container = f.el('toast-container');
    for (let i = 1; i <= 7; i++) f.context.showToast('note ' + i, i === 7 ? undefined : 'info');
    assert.deepEqual(container.children.map(toast => toast.textContent), ['note 3', 'note 4', 'note 5', 'note 6', 'note 7']);
    assert.equal(container.children.at(-1).className, 'toast', 'a toast without a type gets no type class');
    await f.tick(4000);
    assert.ok(container.children.every(toast => toast.classList.contains('toast-out')));
    await f.tick(250);
    assert.equal(container.children.length, 0);
});

test('the connection indicator names the live state, reconnects over ws: on plain HTTP and survives a blocked socket', async () => {
    const f = bootDashboard({ ids: ['connection-status'] });
    await settle();
    const indicator = f.el('connection-status');
    indicator.innerHTML = '<span class="status-dot"></span><span class="status-text">Connecting</span>';
    const label = () => [indicator.className, indicator.querySelector('.status-text').textContent];
    const status = statusSocket(f);
    status.open();
    assert.deepEqual(label(), ['connection-indicator connected', 'Connected']);
    f.context.location.protocol = 'http:';
    status.close();
    assert.deepEqual(label(), ['connection-indicator disconnected', 'Disconnected']);
    await f.tick(2000);
    assert.equal(f.sockets.at(-1).url, 'ws://bridge.test/api/nodes/ws/status');
    const count = f.sockets.length;
    f.context.WebSocket = class { constructor() { throw new Error('blocked by policy'); } };
    f.sockets.at(-1).close();
    await assert.doesNotReject(f.tick(4000));
    assert.equal(f.sockets.length, count);
    assert.deepEqual(label(), ['connection-indicator disconnected', 'Disconnected']);
});

/* -- Cross-protocol entity links and the critical banner ---------------- */

test('an entity seen by another protocol within the hour is linked, case-insensitively, and never to itself', async () => {
    const f = bootDashboard();
    followClock(f);
    await settle();
    const db = f.db;
    db.indexEntity('wifi', 'mac', 'AA:BB:CC:DD:EE:FF');
    db.indexEntity('sdr', 'mac', 'aa:bb:cc:dd:ee:ff');
    db.indexEntity('wifi', 'mac', '');
    const host = f.document.createElement('div');
    host.innerHTML = db.getEntityLinks('bluetooth', 'mac', 'Aa:Bb:Cc:Dd:Ee:Ff');
    const badge = host.querySelector('.entity-link-badge');
    assert.deepEqual([badge.textContent, badge.getAttribute('title')], ['Also: WiFi, SDR', 'Also seen in WiFi, SDR']);
    host.innerHTML = db.getEntityLinks('wifi', 'mac', 'aa:bb:cc:dd:ee:ff');
    assert.equal(host.textContent.trim(), 'Also: SDR', 'a protocol never links to itself');
    assert.equal(db.getEntityLinks('bluetooth', 'mac', '11:22:33:44:55:66'), '');
    assert.equal(db.getEntityLinks('bluetooth', 'mac', ''), '');
    await f.tick(60 * 60000 + 1000);
    assert.equal(db.getEntityLinks('bluetooth', 'mac', 'aa:bb:cc:dd:ee:ff'), '', 'sightings older than an hour are not linked');
});

test('a BSSID also seen by the Bluetooth panel is linked on its Wi-Fi anomaly card', async () => {
    const f = bootDashboard();
    await settle();
    // Only the two panels' anomaly-card renderers are needed, not their polling.
    f.load('wifi.js', 'bluetooth.js');
    const wifi = Object.assign(Object.create(f.context.WifiPanel.prototype), { _selectedWifiIds: {} });
    const bluetooth = Object.assign(Object.create(f.context.BluetoothPanel.prototype), { _selectedBtIds: {} });
    const mac = 'AA:BB:CC:DD:EE:FF';
    bluetooth._renderAnomalyCard({ anomaly_id: 'b-1', device_addr: mac, anomaly_type: 'new_device', severity: 'warning', reasons: [] });
    const host = f.document.createElement('div');
    host.innerHTML = wifi._renderAnomalyCard({ anomaly_id: 'w-1', bssid: mac, anomaly_type: 'rogue_ap', severity: 'warning', reasons: [] });
    assert.match(host.querySelectorAll('.entity-link-badge').map(badge => badge.textContent).join(' '), /BT|Bluetooth/);
});

test('a repeat critical alert says how long ago it was first seen, until the 30-minute memory expires', async () => {
    const f = bootDashboard({ ids: ['critical-banner', 'span:critical-banner-msg', 'button:critical-banner-dismiss'] });
    followClock(f);
    await settle();
    const alerts = alertSocket(f);
    alerts.open();
    const banner = f.el('critical-banner'), msg = f.el('critical-banner-msg');
    alerts.message({ alert_id: 'c-1', severity: 'critical', name: 'Jammer', node_id: 'edge-1', message: 'first' });
    f.el('critical-banner-dismiss').click();
    await f.tick(5 * 60000);
    alerts.message({ alert_id: 'c-1', severity: 'critical', name: 'Jammer', node_id: 'edge-1', message: 'again' });
    assert.equal(msg.textContent, 'again (seen 5m ago)');
    assert.ok(banner.classList.contains('critical-banner-repeat'));
    // Events older than the 60 s coalescing window drop out of the banner text.
    await f.tick(61000);
    alerts.message({ alert_id: 'c-2', severity: 'critical', name: 'Spoofer', message: 'new source' });
    assert.equal(msg.textContent, 'new source');
    assert.ok(!banner.classList.contains('critical-banner-repeat'));
    await f.tick(31 * 60000);
    alerts.message({ alert_id: 'c-1', severity: 'critical', name: 'Jammer', message: 'much later' });
    assert.equal(msg.textContent, 'much later', 'the earlier sighting is forgotten after 30 minutes');
    assert.ok(!banner.classList.contains('critical-banner-repeat'));
    assert.deepEqual(JSON.parse(f.context.localStorage.getItem('bridge_seen_critical_ids')).map(([id]) => id), ['c-1'],
        'expired sightings are dropped from storage too');
    // Callers may still pass plain text (coalesced with the last minute's events); anything else is ignored.
    f.context.showCriticalBanner('plain text banner');
    assert.equal(msg.textContent, 'much later — plain text banner');
    f.context.showCriticalBanner(42);
    assert.equal(msg.textContent, 'much later — plain text banner');
});

test('alert sounds differ by severity and release their audio context once played; a high alert gets a haloed timeline mark', async () => {
    const f = bootDashboard({ ids: ['canvas:threat-timeline-canvas'] });
    await settle();
    const contexts = [], clock = () => f.context.performance.now();
    f.context.AudioContext = class {
        constructor() { this.currentTime = 0; this.destination = {}; this.tones = []; this.openedAt = clock(); this.closedAt = null; contexts.push(this); }
        createOscillator() {
            const osc = { frequency: {}, connect() {}, start: at => { osc.from = at; }, stop: at => { osc.until = at; } };
            this.tones.push(osc);
            return osc;
        }
        createGain() { return { gain: {}, connect() {} }; }
        close() { this.closedAt = clock(); }
    };
    const alerts = alertSocket(f);
    alerts.open();
    const sound = severity => {
        alerts.message({ alert_id: 'a-' + severity, severity, message: severity + ' alert' });
        const ctx = contexts.at(-1);
        return { tones: ctx.tones.length, pattern: JSON.stringify([ctx.tones.map(osc => [osc.frequency.value, osc.type])]) };
    };
    const critical = sound('critical'), warning = sound('warning'), info = sound('info');
    assert.equal(new Set([critical.pattern, warning.pattern, info.pattern]).size, 3, 'each severity has its own sound');
    assert.equal(sound('notice').pattern, info.pattern, 'an unknown severity sounds like info');
    assert.ok(critical.tones > warning.tones && critical.tones > info.tones, 'critical is the longest alarm');
    assert.ok(contexts.every(ctx => ctx.closedAt === null), 'nothing is cut off while it plays');
    await f.tick(10000);
    for (const ctx of contexts) {
        const end = Math.max(...ctx.tones.map(osc => osc.until)) * 1000;
        assert.ok(ctx.closedAt !== null && ctx.closedAt - ctx.openedAt >= end, `closed ${ctx.closedAt - ctx.openedAt} ms in, last tone ends at ${end} ms`);
    }
    const radii = [];
    f.el('threat-timeline-canvas').getContext = () => new Proxy({}, {
        get: (target, name) => (name in target ? target[name] : (...args) => { if (name === 'arc') radii.push(args[2]); }),
        set: (target, name, value) => { target[name] = value; return true; } });
    alerts.message({ alert_id: 'a-high', severity: 'high', message: 'high alert' });
    assert.ok(radii.includes(9), 'the halo ring is drawn around high alerts');
});

test('the threat timeline is seeded from recent alerts and RF anomalies, graded by anomaly score', async () => {
    const now = Date.now();
    const iso = ms => new Date(ms).toISOString();
    const f = bootDashboard({ ids: ['canvas:threat-timeline-canvas', 'threat-timeline-summary'], routes: url => {
        if (url.startsWith('/api/alerts/?limit=50')) return [{ alert_id: 'a-1', triggered_at: iso(now - 120000) },
            { alert_id: 'a-old', triggered_at: iso(now - 40 * 60000), message: 'too old' }, { alert_id: 'a-none' }];
        if (url.startsWith('/api/detections/anomalies')) return { anomalies: [
            { timestamp: iso(now - 60000), anomaly_score: 0.9, signal_class: 'lora' },
            { detected_at: iso(now - 300000), anomaly_score: 0.6 },
            { timestamp: iso(now - 600000) },
            { anomaly_score: 0.95 }] };
        return undefined;
    } });
    followClock(f, now);
    f.document.body.clientWidth = 648;
    await settle();
    const canvas = f.el('threat-timeline-canvas'), summary = f.el('threat-timeline-summary');
    const hover = minutesAgo => {
        const x = (30 - minutesAgo) / 30 * canvas.width;
        for (let y = 0; y <= canvas.height; y += 2) {
            canvas.dispatchEvent(new f.context.Event('mousemove', { clientX: x, clientY: y }));
            if (!summary.hidden) return summary.textContent;
        }
        return null;
    };
    assert.ok(canvas.width > 300 && canvas.width <= 648, 'the timeline is sized to its container: ' + canvas.width);
    assert.match(hover(1), /^SDR observation \(no linked alert\) · critical · .+ · lora anomaly$/);
    assert.match(hover(5), /^SDR observation \(no linked alert\) · warning · .+ · RF anomaly$/);
    assert.match(hover(10), /^SDR observation \(no linked alert\) · info · .+ · RF anomaly$/);
    assert.match(hover(2), /^Alert · info · .+ ·  — Click or press Enter to open Alerts\.$/, 'an alert without severity or message');
    canvas.dispatchEvent(new f.context.Event('mouseleave'));
    assert.equal(summary.hidden, true);
    assert.equal(hover(40), null, 'nothing older than 30 minutes is plotted');
});
