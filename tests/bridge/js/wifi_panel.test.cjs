/* The shipped Wi-Fi SIGINT panel (wifi.js) built from index.html: network
 * table sorting, grouping and paging, band filters, the channel chart, the
 * anomaly workflow (re-evaluate, purge, frames, pcap) and the investigation
 * checklist. Radio-supplied fields are often missing; the panel must say so. */
const assert = require('node:assert/strict');
const test = require('node:test');
const { bootDashboard, response, settle } = require('./untrusted_dom.cjs');

const PANELS = ['panel-wifi', 'wifi-investigate-overlay'];
const NOT_JSON = () => response(503, '<html>unavailable</html>', 'text/html');
const T1 = new Date(2026, 10, 10, 9, 0).toISOString(), T2 = new Date(2026, 10, 10, 9, 30).toISOString();
const AP1 = '02:00:00:00:00:01', AP2 = '02:00:00:00:00:02', AP3 = '02:00:00:00:00:03';

function panel({ networks = [], anomalies = [], routes = () => undefined, activate = true, ...options } = {}) {
    const f = bootDashboard({ ids: [...PANELS, 'sum-wifi-networks', 'sum-wifi-clients', 'sum-wifi-anomalies'], subtrees: PANELS, scripts: ['chart_utils.js', 'wifi.js'],
        ...options, routes: (url, opts, call) => {
            const answer = routes(url, opts, call);
            if (answer !== undefined) return answer;
            if (opts.method && opts.method !== 'GET') return {};
            if (url.startsWith('/api/admin/wifi-whitelist')) return { whitelist: [] };
            if (url.startsWith('/api/wifi/networks')) return { networks };
            if (url.startsWith('/api/wifi/anomalies?min_score=0.3')) return { anomalies, total: anomalies.length };
            return undefined;
        } });
    f.wifi = f.db.wifiPanel;
    if (activate) f.wifi.activate();
    return f;
}
const change = (f, el, value) => { el.value = value; el.dispatchEvent(new f.context.Event('change')); };
const order = f => f.el('wifi-network-tbody').querySelectorAll('.wifi-net-row').map(row => row.getAttribute('data-bssid'));
const urls = (f, prefix) => f.requests.map(call => call.url.replace(/[?&]_t=\d+$/, '')).filter(url => url.startsWith(prefix));
const queue = f => f.el('wifi-anomaly-queue');
const classes = el => el.className.split(/\s+/);
const wifiEvents = f => JSON.parse(JSON.stringify(f.db._tlEvents)).filter(event => event.protocol === 'wifi');
const anomaly = (id, extra = {}) => ({ id, ssid: 'net-' + id, bssid: AP1, channel: 6, band: '2.4GHz', security: 'WPA2',
    signal_dbm: -50, anomaly_score: 0.8, timestamp: T2, ...extra });
/* The same canvas labels, in any drawing order. */
const sameText = (drawn, expected, message) => assert.deepEqual([...drawn].sort(), [...expected].sort(), message);
function canvasText(el) {
    const texts = [];
    el.getContext = () => new Proxy({}, {
        get: (target, key) => (key in target ? target[key] : key === 'fillText' ? text => texts.push(String(text)) : () => ({ addColorStop() {} })),
        set: (target, key, value) => { target[key] = value; return true; },
    });
    return texts;
}

const NETWORKS = [
    { bssid: AP1, ssid: 'Bravo', vendor: 'acme', channel: 11, band: '2.4GHz', security: 'WPA2', avg_signal_dbm: -45, client_count: 3, last_seen: T2 },
    { bssid: AP3, ssid: 'alpha', vendor: 'Zeta', channel: 36, band: '5GHz', security: 'Open', avg_signal_dbm: -75, client_count: 0, last_seen: T1 },
    { bssid: AP2, ssid: '' }];

test('the network table sorts by every column from the select, the direction button and the headers', async () => {
    const f = panel({ networks: NETWORKS });
    await settle();
    const dir = f.el('wifi-net-sort-dir');
    assert.deepEqual(order(f), [AP1, AP3, AP2], 'strongest signal first; an unknown signal sorts as -100 dBm');
    assert.deepEqual([dir.textContent, dir.title], ['▼', 'Descending']);
    dir.click();
    assert.deepEqual([dir.textContent, dir.title], ['▲', 'Ascending']);
    const ascending = { ssid: [AP2, AP3, AP1], bssid: [AP1, AP2, AP3], channel: [AP2, AP1, AP3], band: [AP2, AP1, AP3],
        security: [AP2, AP3, AP1], signal: [AP2, AP3, AP1], clients: [AP3, AP2, AP1], last_seen: [AP2, AP3, AP1] };
    for (const [column, expected] of Object.entries(ascending)) {
        change(f, f.el('wifi-net-sort-select'), column);
        assert.equal(f.el('wifi-net-sort-select').value, column, 'the page offers ' + column);
        assert.deepEqual(order(f), expected, column);
    }
    // Headers: a new column sorts ascending, the same column again flips the direction.
    const header = column => f.document.querySelectorAll('#wifi-network-table th[data-sort]').find(th => th.getAttribute('data-sort') === column);
    header('vendor').click();
    assert.deepEqual(order(f), [AP2, AP1, AP3], 'vendor names sort case-insensitively, unknown first');
    header('vendor').click();
    assert.deepEqual(order(f), [AP3, AP1, AP2]);
    assert.equal(dir.textContent, '▼');
    header('ssid').click();
    assert.deepEqual([order(f), dir.title, f.el('wifi-net-sort-select').value], [[AP2, AP3, AP1], 'Ascending', 'ssid']);
    const hidden = f.el('wifi-network-tbody').querySelector(`[data-bssid="${AP2}"]`).querySelectorAll('td').map(td => td.textContent);
    assert.deepEqual([hidden[0], hidden[2], hidden[5], hidden[8]], ['(hidden)', '', 'Unknown', '--']);
});

test('a network without a signal reading shows a placeholder, not a bare unit', async () => {
    const f = panel({ networks: [{ bssid: AP2, ssid: '' }] });
    await settle();
    assert.match(f.el('wifi-network-tbody').querySelector('.wifi-net-row').querySelectorAll('td')[6].textContent, /--/);
});

test('signal and data rate show their value with the unit, or a bare placeholder, in the network and client tables', async () => {
    const f = panel({ networks: [{ bssid: AP1, ssid: 'a', avg_signal_dbm: -45 }, { bssid: AP2, ssid: 'b', avg_signal_dbm: 0 }, { bssid: AP3, ssid: 'c' }],
        routes: url => (url.startsWith('/api/wifi/clients?bssid=') ? { clients: [{ client_mac: 'aa:bb', avg_signal_dbm: -40, avg_data_rate: 54 },
            { client_mac: 'cc:dd' }] } : undefined) });
    await settle();
    const row = bssid => f.el('wifi-network-tbody').querySelector(`[data-bssid="${bssid}"]`);
    assert.deepEqual([AP1, AP2, AP3].map(bssid => row(bssid).querySelectorAll('td')[6].textContent), ['-45 dBm', '0 dBm', '--']);
    row(AP1).querySelector('td').click();
    await settle();
    assert.deepEqual(f.el('wifi-client-list').querySelectorAll('tbody tr').map(tr => tr.querySelectorAll('td').slice(2, 4).map(td => td.textContent)),
        [['-40 dBm', '54 Mbps'], ['--', '--']]);
});

test('a network whose signal reading is an empty string shows the placeholder', async () => {
    const f = panel({ networks: [{ bssid: AP2, ssid: 'x', avg_signal_dbm: '' }] });
    await settle();
    assert.equal(f.el('wifi-network-tbody').querySelector('.wifi-net-row').querySelectorAll('td')[6].textContent, '--');
});

test('more than 20 networks are paged behind Show all, and grouping shows every row', async () => {
    const networks = Array.from({ length: 25 }, (_, i) => ({ bssid: '02:00:00:00:01:' + String(i).padStart(2, '0'), ssid: 's' + i,
        vendor: i % 2 ? 'acme' : undefined, security: i % 3 ? 'WPA2' : '', band: i < 5 ? '5GHz' : undefined, channel: i < 5 ? 36 : 0,
        avg_signal_dbm: -40 - i }));
    const f = panel({ networks });
    await settle();
    const wrap = f.el('wifi-network-tbody').closest('.table-wrap');
    const toggle = () => f.el('wifi-table-toggle');
    assert.equal(order(f).length, 20);
    assert.ok(toggle().parentNode === wrap, 'the pager sits under the network table');
    assert.equal(toggle().textContent, 'Show all 25 networks (5 more)');
    assert.equal(wrap.style.maxHeight, '');
    f.el('wifi-table-expand').click();
    assert.equal(order(f).length, 25);
    assert.equal(toggle().textContent, 'Collapse to 20');
    assert.deepEqual([wrap.style.maxHeight, wrap.style.overflowY], ['600px', 'auto']);
    f.el('wifi-table-expand').click();
    assert.equal(order(f).length, 20);
    assert.deepEqual([wrap.style.maxHeight, wrap.style.overflowY], ['', '']);

    const groups = () => f.el('wifi-network-tbody').querySelectorAll('.wifi-net-group-header').map(row => row.textContent.slice(2));
    change(f, f.el('wifi-net-group-select'), 'vendor');
    assert.deepEqual(groups(), ['Vendor: Unknown (13)', 'Vendor: acme (12)']);
    assert.equal(order(f).length, 25, 'grouped tables are not paged');
    assert.equal(toggle().style.display, 'none');
    change(f, f.el('wifi-net-group-select'), 'security');
    assert.deepEqual(groups(), ['Security: WPA2 (16)', 'Security: Unknown (9)']);
    change(f, f.el('wifi-net-group-select'), 'band');
    assert.deepEqual(groups(), ['Band: Unknown (20)', 'Band: 5GHz (5)']);
    change(f, f.el('wifi-net-group-select'), 'channel');
    assert.deepEqual(groups(), ['Channel: ? (20)', 'Channel: 36 (5)']);
    change(f, f.el('wifi-net-group-select'), '');
    assert.equal(order(f).length, 20);
});

test('the authorization filter and whitelisting work for an AP that broadcasts no SSID', async () => {
    const AP = '0A:BB:CC:00:00:01';  // the whitelist may store it in lower case
    let whitelist = {}, add = {};
    const f = panel({ networks: [{ bssid: AP, ssid: '' }, { bssid: AP2, ssid: 'Corp' }, { ssid: 'no-bssid' }], routes: (url, opts) => {
        if (url.startsWith('/api/admin/wifi-whitelist')) return opts.method === 'POST' ? add : whitelist;
        return undefined;
    } });
    await settle();
    change(f, f.el('wifi-net-show-select'), 'authorized');
    assert.equal(f.el('wifi-network-tbody').textContent, 'No authorized networks', 'a whitelist reply without entries authorizes nothing');
    change(f, f.el('wifi-net-show-select'), 'all');
    const button = f.el('wifi-network-tbody').querySelector(`[data-wl-bssid="${AP}"]`);
    f.answerConfirm(true);
    whitelist = { whitelist: [{ bssid: AP.toLowerCase(), id: 7 }] };
    button.click();
    assert.ok(f.dialogs.at(-1)[1].startsWith('Whitelist AP ' + AP + '?'), 'no empty SSID in the prompt');
    await settle();
    assert.deepEqual(f.body(f.lastWrite()), { bssid: AP, ssid: '' });
    assert.equal(f.toasts().at(-1), 'Whitelisted ' + AP);
    change(f, f.el('wifi-net-show-select'), 'authorized');
    assert.deepEqual(order(f), [AP], 'the reloaded whitelist authorizes the AP by its BSSID in any case');
    change(f, f.el('wifi-net-show-select'), 'unauthorized');
    assert.deepEqual(order(f), [AP2, ''], 'a network without a BSSID is never authorized');
    // A whitelist reply without entries clears what was authorized before.
    whitelist = {};
    f.el('wifi-network-tbody').querySelector('[data-wl-bssid]').click();
    await settle();
    change(f, f.el('wifi-net-show-select'), 'authorized');
    assert.equal(f.el('wifi-network-tbody').textContent, 'No authorized networks');
    change(f, f.el('wifi-net-show-select'), 'unauthorized');
    add = NOT_JSON();
    f.el('wifi-network-tbody').querySelector('[data-wl-bssid]').click();
    await settle();
    assert.equal(f.toasts().at(-1), 'Whitelist failed: HTTP 503');
});

test('a whitelisted AP shows as authorized once the whitelist has reloaded', async () => {
    let whitelist = { whitelist: [] };
    const f = panel({ networks: NETWORKS, routes: (url, opts) => (url.startsWith('/api/admin/wifi-whitelist') && (opts.method || 'GET') === 'GET' ? whitelist : undefined) });
    await settle();
    whitelist = { whitelist: [{ bssid: AP1, id: 1 }] };
    f.el('wifi-network-tbody').querySelector(`[data-wl-bssid="${AP1}"]`).click();
    await settle();
    assert.equal(f.el('wifi-network-tbody').querySelector(`[data-bssid="${AP1}"]`).querySelectorAll('td')[9].textContent, 'Authorized');
});

test('selecting a network loads its clients and signal history, and reports failures with a retry', async () => {
    let clients = { clients: [{ client_mac: 'aa:bb', avg_signal_dbm: -40, avg_data_rate: 54, frame_count: 2, last_seen: T1 }] };
    let timeline = { timeline: [{ avg_signal_dbm: -50 }, { avg_signal_dbm: -55 }] };
    const f = panel({ activate: false, networks: NETWORKS, routes: url => {
        if (url.startsWith('/api/wifi/clients?bssid=')) return clients;
        if (url.startsWith('/api/wifi/timeline?bssid=')) return timeline;
        return undefined;
    } });
    const sparklines = [];
    const draw = f.context.ChartUtils.drawSparkline;
    f.context.ChartUtils.drawSparkline = (...args) => { sparklines.push(JSON.parse(JSON.stringify(args[2]))); return draw(...args); };
    f.wifi.activate();
    await settle();
    const row = bssid => f.el('wifi-network-tbody').querySelector(`[data-bssid="${bssid}"]`);
    f.answerConfirm(false);
    row(AP1).querySelector('[data-wl-bssid]').click();
    assert.equal(urls(f, '/api/wifi/clients').length, 0, 'nor does the Whitelist button');
    row(AP1).querySelector('td').click();
    await settle();
    assert.equal(row(AP1).style.background, 'var(--bg-hover)');
    assert.deepEqual(urls(f, '/api/wifi/timeline'), ['/api/wifi/timeline?bssid=' + encodeURIComponent(AP1) + '&hours=24']);
    assert.deepEqual(f.el('wifi-client-list').querySelectorAll('td').map(td => td.textContent).slice(0, 2), ['aa:bb', '--']);
    assert.equal(f.el('wifi-client-empty').style.display, 'none');
    assert.deepEqual(sparklines, [[-50, -55]]);

    clients = {};
    timeline = { timeline: [] };
    row(AP3).querySelector('td').click();
    await settle();
    assert.deepEqual([row(AP1).style.background, row(AP3).style.background], ['', 'var(--bg-hover)']);
    assert.equal(f.el('wifi-client-list').textContent, '');
    assert.equal(f.el('wifi-client-empty').style.display, '');
    assert.equal(sparklines.length, 1, 'an empty history draws nothing');

    clients = NOT_JSON();
    timeline = NOT_JSON();
    const drawn = canvasText(f.el('wifi-signal-canvas'));
    row(AP2).querySelector('td').click();
    await settle();
    assert.ok(f.el('wifi-client-list').textContent.includes('Failed to load client data'));
    assert.deepEqual(drawn, ['Failed to load signal timeline']);
    clients = { clients: [{ client_mac: 'cc:dd', ssid: 'Corp' }] };
    f.el('wifi-client-list').querySelector('.retry-btn').click();
    await settle();
    assert.equal(urls(f, '/api/wifi/clients').at(-1), '/api/wifi/clients?bssid=' + encodeURIComponent(AP2), 'Retry reloads the same network');
    assert.equal(f.el('wifi-client-list').querySelector('code').textContent, 'cc:dd');
});

test('band buttons narrow the network list and the channel chart to one band', async () => {
    let channels = { '2.4GHz': { channels: [] }, '5GHz': {}, '6GHz': {} };
    const f = panel({ activate: false, routes: url => {
        const band = /^\/api\/wifi\/channels\?band=([^&]+)/.exec(url);
        if (band) return channels[decodeURIComponent(band[1])];
        return undefined;
    } });
    const drawn = canvasText(f.el('wifi-channel-canvas'));
    f.wifi.activate();
    await f.tick(500);
    assert.deepEqual(drawn, ['Loading channel data...', 'No channel data']);
    assert.deepEqual(urls(f, '/api/wifi/channels'), ['/api/wifi/channels?band=2.4GHz', '/api/wifi/channels?band=5GHz', '/api/wifi/channels?band=6GHz']);

    // One band failing does not hide the others; bands are drawn in order with their labels.
    channels = { '2.4GHz': { channels: [{ band: '2.4GHz', channel: 6, frame_count: 40, network_count: 3, utilization_pct: 80 }] },
        '5GHz': NOT_JSON(), '6GHz': { channels: [{ band: 'weird', channel: 1, frame_count: 0 }, { band: '5GHz', channel: 36, frame_count: 10, network_count: 2 }] } };
    drawn.length = 0;
    await f.tick(15000);
    sameText(drawn.slice(1), ['6', '3', '36', '2', '1', '2.4GHz', '5GHz', 'weird']);

    const toggle = f.el('wifi-band-toggle');
    const button = band => toggle.querySelectorAll('[data-wifi-band]').find(b => b.getAttribute('data-wifi-band') === band);
    const requests = f.requests.length;
    channels = { '5GHz': { channels: [{ band: '5GHz', channel: 40, frame_count: 5 }] } };
    drawn.length = 0;
    button('5GHz').click();
    await settle();
    assert.ok(button('5GHz').classList.contains('active') && !button('all').classList.contains('active'));
    assert.deepEqual(f.requests.slice(requests).map(call => call.url.replace(/[?&]_t=\d+$/, '')),
        ['/api/wifi/networks?limit=100&band=5GHz', '/api/wifi/channels?band=5GHz']);
    sameText(drawn.slice(1), ['40', '5GHz']);
    channels = {};
    button('6GHz').click();
    await settle();
    assert.equal(drawn.at(-1), 'No channel data', 'a band with no reply draws as empty');
    channels = { '6GHz': NOT_JSON() };
    button('6GHz').click();
    await settle();
    assert.equal(drawn.at(-1), 'No channel data', 'a failed band shows no stale bars');
});

test('Wi-Fi stats fill the panel and Summary, with placeholders for missing counts', async () => {
    let stats = { total_networks: 12, total_clients: 30, busiest_channel: 6, wifi_node_ids: ['n1'],
        band_breakdown: { '2.4GHz': { network_count: 8 }, '5GHz': { network_count: 4 } } };
    const f = panel({ routes: url => (url.startsWith('/api/wifi/stats') ? stats : undefined) });
    await f.tick(1000);
    const shown = () => ['networks', 'clients', 'channel', '24g', '5g'].map(name => f.el('wifi-stat-' + name).textContent);
    assert.deepEqual(shown(), ['12', '30', '6', '8', '4']);
    assert.deepEqual([f.el('sum-wifi-networks').textContent, f.el('sum-wifi-clients').textContent], ['12', '30']);
    assert.deepEqual([...f.db.wifiNodeIds], ['n1']);
    stats = {};
    await f.tick(20000);
    assert.deepEqual(shown(), ['--', '--', '--', '0', '0']);
    assert.deepEqual([...f.db.wifiNodeIds], ['n1'], 'a reply without node IDs keeps the known Wi-Fi nodes');
    stats = NOT_JSON();
    await f.tick(20000);
    assert.ok(f.el('wifi-stats-bar').textContent.includes('Failed to load WiFi stats'));
});

test('the anomaly badge shows when the queue is larger than one page, and a reply without anomalies empties it', async () => {
    let reply = { anomalies: [anomaly(1), anomaly(2)], total: 53 };
    const f = panel({ routes: url => (url.startsWith('/api/wifi/anomalies?min_score=0.3') ? reply : undefined) });
    await f.tick(1500);
    assert.equal(f.el('wifi-anomaly-count-badge').textContent, '2 / 53');
    assert.equal(f.el('sum-wifi-anomalies').textContent, '53');
    reply = {};
    await f.tick(8000);
    assert.equal(f.el('wifi-anomaly-count-badge').textContent, '0');
    assert.equal(queue(f).textContent, '');
    assert.equal(f.el('wifi-anomaly-empty').style.display, '');
});

test('polling starts once and stops on deactivation', async () => {
    const f = panel();
    f.wifi.activate();
    assert.equal(urls(f, '/api/wifi/networks').length, 1);
    await f.tick(8000);
    assert.equal(urls(f, '/api/wifi/networks').length, 2);
    f.wifi.deactivate();
    await f.tick(30000);
    assert.equal(urls(f, '/api/wifi/networks').length, 2);
    assert.equal(urls(f, '/api/wifi/anomalies?min_score=0.3').length, 2, 'the 1.5 s first load and one 8 s refresh');
});

test('grouping anomalies by attack, priority or a missing field orders groups by their worst score', async () => {
    const anomalies = [
        anomaly(1, { attack_type: 'evil_twin', anomaly_score: 0.4, frame_count: 5, deauth_count: 2, ssid: 'a' }),
        anomaly(2, { dimensions: { deauth_indicator: 0.9, new_network: 0.2 }, anomaly_score: 0.9, frame_count: 1, ssid: 'b', node_id: 'n1' }),
        anomaly(3, { dimensions: 'bogus', anomaly_score: undefined, ssid: '' }),
        anomaly(4, { dimensions: { channel_change: 0.5, evil_twin: 0 }, anomaly_score: 0.6, deauth_count: 3, ssid: 'd' })];
    const f = panel({ anomalies });
    await f.tick(1500);
    const groups = () => queue(f).querySelectorAll('.wifi-mac-group').map(group => [group.querySelector('strong').textContent,
        group.querySelector('.anomaly-group-badge').textContent, classes(group).find(c => c.startsWith('priority-'))]);
    change(f, f.el('wifi-anomaly-group-select'), 'attack');
    assert.deepEqual(groups(), [['attack: deauth_indicator', '1', 'priority-critical'], ['attack: channel_change', '1', 'priority-anomalous'],
        ['attack: evil_twin', '1', 'priority-interesting'], ['attack: unknown', '1', 'priority-normal']]);
    change(f, f.el('wifi-anomaly-group-select'), 'priority');
    assert.deepEqual(groups().map(([label, count]) => [label, count]), [['priority: critical', '1'], ['priority: anomalous', '1'],
        ['priority: interesting', '1'], ['priority: normal', '1']]);
    change(f, f.el('wifi-anomaly-group-select'), 'node_id');
    assert.deepEqual(groups().map(([label, count]) => [label, count]), [['node_id: n1', '1'], ['node_id: unknown', '3']]);
    const unknown = queue(f).querySelectorAll('.wifi-mac-group')[1];
    assert.ok(unknown.textContent.includes('Events: 3') && unknown.textContent.includes('Frames: 5'));
    assert.equal(unknown.querySelector('.deauth-highlight').textContent, 'Deauth: 5');
    assert.ok(!queue(f).querySelectorAll('.wifi-mac-group')[0].querySelector('.deauth-highlight'), 'no deauth badge without deauths');
    const toggle = unknown.querySelector('[data-wifi-mac-toggle]');
    toggle.click();
    toggle.click();
    assert.equal(unknown.querySelector('.wifi-mac-group-items').style.display, 'none', 'a second click folds the group again');

    // The attack filter lists every active dimension and matches anomalies where it is active.
    change(f, f.el('wifi-anomaly-group-select'), '');
    change(f, f.el('wifi-anomaly-filter-key'), 'attack');
    assert.deepEqual(f.el('wifi-anomaly-filter-val').options.map(o => o.value), ['', 'channel_change', 'deauth_indicator', 'new_network']);
    change(f, f.el('wifi-anomaly-filter-val'), 'new_network');
    assert.deepEqual(queue(f).querySelectorAll('[data-wifi-bulk-id]').map(box => box.getAttribute('data-wifi-bulk-id')), ['2']);
    change(f, f.el('wifi-anomaly-filter-key'), 'priority');
    change(f, f.el('wifi-anomaly-filter-val'), 'normal');
    assert.deepEqual(queue(f).querySelectorAll('[data-wifi-bulk-id]').map(box => box.getAttribute('data-wifi-bulk-id')), ['3']);
    change(f, f.el('wifi-anomaly-filter-key'), 'band');
    assert.deepEqual(f.el('wifi-anomaly-filter-val').options.map(o => o.value), ['', '2.4GHz']);
    change(f, f.el('wifi-anomaly-filter-key'), '');
    assert.equal(f.el('wifi-anomaly-filter-val').style.display, 'none');
    assert.equal(queue(f).querySelectorAll('.anomaly-card').length, 4);
});

test('a filter that matches nothing says so instead of showing an empty queue', async () => {
    const anomalies = [anomaly(1, { ssid: 'a' })];
    const f = panel({ anomalies });
    await f.tick(1500);
    change(f, f.el('wifi-anomaly-filter-key'), 'ssid');
    change(f, f.el('wifi-anomaly-filter-val'), 'a');
    anomalies.splice(0, 1, anomaly(2, { ssid: 'b' }));
    await f.tick(8000);
    assert.equal(queue(f).textContent, 'No anomalies match filter');
    assert.equal(f.el('wifi-anomaly-empty').style.display, 'none', 'the queue is not empty, only filtered');
});

test('anomaly cards show re-evaluation, forensic context and capture controls only when the data exists', async () => {
    const anomalies = [
        anomaly(1, { reeval: { still_anomalous: false, score_delta: -0.25, new_score: 0.4 }, signal_dbm: null, ssid: '', noise_dbm_max: -90,
            expected_signal: -48.2, signal_zscore: 2.5, expected_channel: 11, baseline_observations: 12, seen_count: 4, retry_rate: 0.125,
            frame_type_counts: { beacon: 0 }, has_pcap_capture: true, pcap_frame_count: 0, frame_count: 0 }),
        anomaly(2, { reeval: { still_anomalous: true, score_delta: 0.1, new_score: 0.9 }, expected_signal: -60, seen_count: 1,
            has_pcap_capture: true, pcap_frame_count: 7, dimensions: { evil_twin: 0, custom_dim: 0.3 } }),
        anomaly(3, { reeval: { still_anomalous: true, new_score: 0.8 } })];
    const f = panel({ anomalies });
    await f.tick(1500);
    const [resolved, active, same] = queue(f).querySelectorAll('.anomaly-card');
    assert.ok(resolved.classList.contains('anomaly-resolved') && !active.classList.contains('anomaly-resolved'));
    assert.deepEqual([resolved, active, same].map(card => card.querySelector('.reeval-badge').textContent), ['Resolved', 'Active', 'Active']);
    assert.deepEqual([resolved, active, same].map(card => [card.querySelector('.score-change').textContent,
        classes(card.querySelector('.score-change')).at(-1)]), [['-0.250', 'decreased'], ['+0.100', 'increased'], ['0.000', 'same']]);
    assert.equal(resolved.querySelector('strong').textContent, '(hidden)');
    for (const text of ['Retry: 12.5%', 'Noise: -90 dBm', 'Exp sig: -48.2 dBm (z=2.5)', 'Exp ch: 11', 'Baseline: 12 obs', 'seen 4x']) {
        assert.ok(resolved.textContent.includes(text), text);
    }
    assert.ok(active.textContent.includes('Exp sig: -60.0 dBm (z=--)') && active.textContent.includes('Retry: --'));
    assert.ok(!active.textContent.includes('seen 1x') && !active.textContent.includes('Exp ch:') && !active.textContent.includes('Noise:'));
    assert.ok(!resolved.querySelector('.frame-type-bar'), 'no frame bar when no frames were counted');
    assert.ok(!resolved.querySelector('[data-wifi-frames]'), 'no frame list without frames');
    assert.deepEqual([resolved, active].map(card => card.querySelector('.btn-pcap').textContent), ['pcap', 'pcap (7)']);
    assert.ok(!same.querySelector('.btn-pcap'));
    assert.deepEqual(active.querySelectorAll('.dim-tag').map(tag => [tag.textContent, tag.getAttribute('title')]), [['custom_dim: 0.30', '']],
        'only active dimensions are listed; an unknown one has no description');
});

test('the cross-protocol timeline gets each critical or anomalous Wi-Fi anomaly, labelled by SSID, then BSSID', async () => {
    const f = panel({ anomalies: [anomaly(1, { ssid: 'Corp', anomaly_score: 0.9 }), anomaly(2, { ssid: '', anomaly_score: 0.55 }),
        anomaly(3, { ssid: '', bssid: '', anomaly_score: 0.7 }), anomaly(4, { anomaly_score: 0.45 })] });
    await f.tick(1500);
    assert.deepEqual(wifiEvents(f).map(event => [event.severity, event.label]),
        [['critical', 'Corp'], ['anomalous', AP1], ['critical', 'Unknown WiFi']]);
    change(f, f.el('wifi-anomaly-group-select'), 'ssid');
    assert.equal(wifiEvents(f).length, 3, 're-rendering pushes nothing again');
});

test('a Wi-Fi anomaly reaches the threat timeline once, not on every refresh', async () => {
    const f = panel({ anomalies: [anomaly(1, { anomaly_score: 0.9 })] });
    await f.tick(1500);
    await f.tick(16000);
    assert.equal(wifiEvents(f).length, 1);
});

test('a Wi-Fi anomaly without a row ID is still pushed once across refreshes, and one that leaves and returns is pushed again', async () => {
    const anomalies = [anomaly(null, { anomaly_score: 0.9, anomaly_type: 'rogue_ap' })];
    const f = panel({ anomalies });
    await f.tick(1500);
    await f.tick(16000);
    assert.equal(wifiEvents(f).length, 1);
    const kept = anomalies.splice(0);
    await f.tick(8000);
    anomalies.push(...kept);
    await f.tick(8000);
    assert.equal(wifiEvents(f).length, 2, 'a returning anomaly is news again');
});

test('re-evaluating Wi-Fi anomalies shows the summary and dismisses only resolved anomalies with an ID', async () => {
    const reevaluated = [anomaly(1, { reeval: { still_anomalous: true, new_score: 0.9 }, anomaly_score: 0.5 }),
        anomaly(2, { reeval: { still_anomalous: false, new_score: 0.1 }, anomaly_score: 0.9 }),
        anomaly(3, { reeval: { still_anomalous: false, new_score: 0.1 }, anomaly_score: 0.7 }),
        anomaly(null, { reeval: { still_anomalous: false, new_score: 0.1 } }), anomaly(5, { anomaly_score: 0.95 })];
    let reeval = { anomalies: reevaluated, total: 60, reeval_summary: { still_anomalous: 2, resolved: 3 } }, dismiss = {};
    const f = panel({ anomalies: [anomaly(9)], routes: (url, opts) => {
        if (url.startsWith('/api/wifi/anomalies?min_score=0.3&limit=50&reevaluate=true')) return reeval;
        if (url === '/api/wifi/anomalies/bulk/dismiss' && opts.method === 'PUT') return dismiss;
        return undefined;
    } });
    await f.tick(1500);
    const button = f.el('wifi-reeval-all-btn'), resolved = f.el('wifi-dismiss-resolved-btn'), bar = f.el('wifi-reeval-summary');
    button.click();
    assert.deepEqual([button.disabled, button.textContent], [true, 'Evaluating...']);
    await settle();
    assert.deepEqual([button.disabled, button.textContent], [false, 'Re-evaluate All']);
    assert.deepEqual(bar.querySelectorAll('.reeval-badge').map(el => el.textContent), ['2 still anomalous', '3 resolved']);
    assert.deepEqual([bar.style.display, resolved.style.display], ['', '']);
    assert.equal(f.el('wifi-anomaly-count-badge').textContent, '5 / 60');
    // The anomaly without an ID has a disabled box with no ID of its own.
    assert.deepEqual(queue(f).querySelectorAll('.bulk-checkbox').map(box => box.getAttribute('data-wifi-bulk-id') || ''), ['5', '1', '2', '', '3'],
        'still-anomalous first, each part by score');
    f.answerConfirm(false);
    resolved.click();
    assert.equal(f.dialogs.at(-1)[1], 'Dismiss 2 resolved anomalies?');
    assert.equal(f.writes().length, 0);
    f.answerConfirm(true);
    reeval = { anomalies: [anomaly(1)], reeval_summary: { still_anomalous: 1, resolved: 0 } };
    resolved.click();
    await settle();
    assert.deepEqual(f.body(f.lastWrite()), { ids: [2, 3] });
    assert.equal(f.toasts().at(-1), 'Dismissed 2 resolved anomalies');
    assert.equal(resolved.style.display, 'none');
    assert.equal(f.el('wifi-anomaly-count-badge').textContent, '1');
    reeval = { anomalies: [reevaluated[3]], reeval_summary: { still_anomalous: 0, resolved: 1 } };
    button.click();
    await settle();
    assert.equal(resolved.style.display, '');
    resolved.click();
    assert.equal(f.toasts().at(-1), 'No resolved anomalies to dismiss', 'a resolved anomaly without an ID cannot be dismissed');
    reeval = { anomalies: reevaluated, reeval_summary: { still_anomalous: 2, resolved: 3 } };
    button.click();
    await settle();
    dismiss = NOT_JSON();
    resolved.click();
    await settle();
    assert.equal(f.toasts().at(-1), 'Bulk dismiss failed');
    reeval = NOT_JSON();
    button.click();
    await settle();
    assert.equal(f.toasts().at(-1), 'Re-evaluation failed');
    assert.deepEqual([button.disabled, button.textContent], [false, 'Re-evaluate All']);
    reeval = {};
    button.click();
    await settle();
    assert.equal(bar.style.display, 'none', 'a reply without a summary hides the bar');
    assert.equal(f.el('wifi-anomaly-empty').style.display, '');
});

test('Purge Resolved confirms, reports the server totals and refreshes the queue', async () => {
    let purge = { processed: 10, dismissed: 4, still_anomalous: 6, errors: 1 };
    const f = panel({ routes: (url, opts) => {
        if (url === '/api/wifi/anomalies/bulk/reeval-dismiss' && opts.method === 'POST') return purge;
        if (url.startsWith('/api/wifi/anomalies?min_score=0.3')) return { anomalies: [anomaly(1), anomaly(2)], total: 60 };
        return undefined;
    } });
    await f.tick(1500);
    const button = f.el('wifi-reeval-dismiss-all-btn');
    f.answerConfirm(false);
    button.click();
    assert.ok(f.dialogs.at(-1)[1].includes('This will process all 60 anomalies server-side.'), 'the whole queue, not the loaded page');
    assert.equal(f.writes().length, 0);
    f.answerConfirm(true);
    const polls = urls(f, '/api/wifi/anomalies?min_score=0.3').length;
    button.click();
    assert.deepEqual([button.disabled, button.textContent], [true, 'Processing...']);
    await settle();
    assert.equal(f.toasts().at(-1), '10 evaluated: 4 dismissed, 6 remain (1 errors)');
    assert.deepEqual([button.disabled, button.textContent], [false, 'Purge Resolved']);
    assert.equal(urls(f, '/api/wifi/anomalies?min_score=0.3').length, polls + 1);
    purge = { processed: 2, dismissed: 0, still_anomalous: 2, errors: 0 };
    button.click();
    await settle();
    assert.equal(f.toasts().at(-1), '2 evaluated: 0 dismissed, 2 remain');
    purge = NOT_JSON();
    button.click();
    await settle();
    assert.equal(f.toasts().at(-1), 'Purge failed');
    assert.deepEqual([button.disabled, button.textContent], [false, 'Purge Resolved']);
});

test('single and group re-evaluation results land on the exact anomaly cards', async () => {
    let single = { still_anomalous: true, score_delta: 0, new_score: 0.5, original_score: 0.5, baseline_status: 'stable', baseline_observations: 3,
        normal_since: T1 };
    let bulk = { results: { 1: { still_anomalous: false, score_delta: -0.3, new_score: 0.2 }, 2: { still_anomalous: true, score_delta: 0, new_score: 0.6 } } };
    const f = panel({ anomalies: [anomaly(1, { ssid: 'x' }), anomaly(2, { ssid: 'x', anomaly_score: 0.6 })], routes: (url, opts) => {
        if (url === '/api/wifi/anomalies/1/reevaluate' && opts.method === 'POST') return single;
        if (url === '/api/wifi/anomalies/bulk/reevaluate' && opts.method === 'POST') return bulk;
        return undefined;
    } });
    await f.tick(1500);
    const reevalButton = () => queue(f).querySelector('[data-wifi-reeval="1"]');
    reevalButton().click();
    assert.deepEqual([reevalButton().disabled, reevalButton().textContent], [true, 'Evaluating...']);
    await settle();
    const result = f.el('wifi-reeval-1');
    assert.deepEqual([reevalButton().disabled, reevalButton().textContent], [false, 'Re-evaluate']);
    assert.equal(result.style.display, '');
    assert.equal(result.querySelector('.reeval-badge').textContent, 'Still Anomalous');
    assert.ok(result.querySelector('.score-change').classList.contains('same'));
    assert.ok(result.textContent.includes('normal since') && !result.textContent.includes('Reasons:'));
    single = { still_anomalous: true, score_delta: 0.15, new_score: 0.65, original_score: 0.5, baseline_status: 'drift', baseline_observations: 4 };
    reevalButton().click();
    await settle();
    assert.equal(result.querySelector('.score-change').textContent, '+0.150');
    assert.ok(result.querySelector('.score-change').classList.contains('increased') && !result.textContent.includes('normal since'));
    single = NOT_JSON();
    reevalButton().click();
    await settle();
    assert.equal(f.toasts().at(-1), 'Re-evaluation failed');
    assert.deepEqual([reevalButton().disabled, reevalButton().textContent], [false, 'Re-evaluate']);

    change(f, f.el('wifi-anomaly-group-select'), 'ssid');
    const group = queue(f).querySelector('.wifi-mac-group');
    const bulkButton = group.querySelector('[data-wifi-reeval-bulk]');
    bulkButton.click();
    assert.deepEqual([bulkButton.disabled, bulkButton.textContent], [true, 'Evaluating...']);
    await settle();
    const summary = group.querySelector('[id^="wifi-reeval-group-"]');
    assert.equal(summary.style.display, '');
    assert.deepEqual(summary.querySelectorAll('.reeval-badge').map(el => el.textContent), ['1 normal', '1 anomalous']);
    assert.ok(summary.textContent.startsWith('2 re-evaluated:'));
    assert.deepEqual(['wifi-reeval-1', 'wifi-reeval-2'].map(id => [f.el(id).querySelector('.reeval-badge').textContent,
        classes(f.el(id).querySelector('.score-change')).at(-1)]), [['Now Normal', 'decreased'], ['Still Anomalous', 'same']]);
    bulk = {};
    bulkButton.click();
    await settle();
    assert.ok(summary.textContent.startsWith('0 re-evaluated:'), 'a reply without results re-evaluated nothing');
    bulk = NOT_JSON();
    bulkButton.click();
    await settle();
    assert.equal(f.toasts().at(-1), 'Re-evaluation failed');
    assert.deepEqual([bulkButton.disabled, bulkButton.textContent], [false, 'Re-evaluate All']);
    f.answerConfirm(true);
    group.querySelector('[data-wifi-dismiss-bulk]').click();
    await settle();
    assert.equal(f.toasts().at(-1), 'Dismissed 2 WiFi anomalies');
});

test('captured frames and the pcap summary load once, fold away and report failures', async () => {
    const frames = Array.from({ length: 25 }, (_, i) => (i ? { frame_type: 'data', client_mac: 'aa:bb:cc:dd:ee:' + i, signal_dbm: -40, data_rate_mbps: 54, retry_flag: 1 } : {}));
    let capture = { anomalies: [{ id: 99 }, { id: 1, frame_capture: frames }, { id: 2 }] };
    let summary = { total_frames: 40, duration_ms: 12, frame_types: {}, frames: Array.from({ length: 31 }, (_, i) => (i ? { frame_type: 'beacon', length: 64 } : {})) };
    const f = panel({ anomalies: [anomaly(1, { frame_count: 25, has_pcap_capture: true }), anomaly(2, { frame_count: 3, has_pcap_capture: true }),
        anomaly(3, { frame_count: 1, has_pcap_capture: true })],
        routes: url => {
            if (url.startsWith('/api/wifi/anomalies?include_frames=true')) return capture;
            if (/^\/api\/wifi\/anomalies\/\d+\/pcap\/summary/.test(url)) return summary;
            return undefined;
        } });
    await f.tick(1500);
    const content = id => f.el('pcap-wrap-' + id).querySelector('.pcap-content');
    const frameButton = id => queue(f).querySelector(`[data-wifi-frames="${id}"]`);
    frameButton(1).click();
    await settle();
    const rows = content(1).querySelectorAll('tbody tr').map(tr => tr.querySelectorAll('td').map(td => td.textContent));
    assert.equal(rows.length, 20);
    assert.deepEqual(rows[0], ['--', '--', '--', '--', '--']);
    assert.deepEqual(rows[1], ['data', '...:ee:1', '-40', '54', '1']);
    assert.equal(content(1).querySelector('.pcap-more').textContent, 'and 5 more...');
    frameButton(1).click();
    assert.equal(content(1).style.display, 'none');
    frameButton(1).click();
    assert.equal(content(1).style.display, '');
    assert.equal(urls(f, '/api/wifi/anomalies?include_frames=true').length, 1, 'loaded frames are not fetched again');
    frameButton(2).click();
    await settle();
    assert.equal(content(2).textContent, 'No frames captured');
    capture = NOT_JSON();
    frameButton(3).click();
    await settle();
    assert.equal(content(3).textContent, 'Failed to load');

    const pcap = id => f.el('pcap-summary-' + id);
    const summaryButton = id => queue(f).querySelector(`[data-pcap-summary="${id}"]`);
    summaryButton(1).click();
    assert.equal(pcap(1).textContent, 'Loading pcap summary...');
    await settle();
    assert.ok(pcap(1).textContent.includes('Size: 0 KB'));
    assert.ok(!pcap(1).querySelector('.frame-type-bar'), 'no type breakdown without frame types');
    assert.equal(pcap(1).querySelectorAll('tbody tr').length, 30);
    assert.deepEqual(pcap(1).querySelector('tbody tr').querySelectorAll('td').map(td => td.textContent), ['1', 'unknown', '--']);
    assert.equal(pcap(1).querySelector('.pcap-more').textContent, 'and 1 more frames...');
    summaryButton(1).click();
    assert.equal(pcap(1).style.display, 'none');
    summaryButton(1).click();
    assert.equal(pcap(1).style.display, '');
    assert.equal(urls(f, '/api/wifi/anomalies/1/pcap/summary').length, 1);
    summary = { total_frames: 0, duration_ms: 0, size_bytes: 4096 };
    summaryButton(2).click();
    await settle();
    assert.ok(pcap(2).textContent.includes('Size: 4 KB') && !pcap(2).querySelector('table'));
    summary = NOT_JSON();
    summaryButton(3).click();
    await settle();
    assert.equal(pcap(3).textContent, 'Failed to load pcap summary');
});

test('the Wi-Fi investigation checklist grades score, dimensions, deauths, signal and capture evidence', async () => {
    const cases = {
        1: [{ anomaly_score: 0.2 }, 'Add to baseline', ['pass', 'pass', 'pass', 'unknown', 'warn', 'pass']],
        2: [{ anomaly_score: 0.35, dimensions: { new_network: 0.4, client_surge: 0.2 }, deauth_count: 3, signal_zscore: 1.2, frame_count: 4 },
            'Investigate further', ['warn', 'warn', 'warn', 'pass', 'warn', 'warn']],
        3: [{ anomaly_score: 0.55, dimensions: { security_downgrade: 0.6 }, deauth_count: 12, signal_zscore: -3.5, has_pcap_capture: true, pcap_frame_count: 9 },
            'Escalate', ['warn', 'fail', 'fail', 'fail', 'pass', 'fail']],
        4: [{ anomaly_score: 0.75, signal_zscore: 2.5, has_pcap_capture: true }, 'Escalate', ['fail', 'pass', 'pass', 'warn', 'pass', 'warn']],
        5: [{ anomaly_score: 0.6, signal_zscore: 0.5, has_pcap_capture: true }, 'Add to baseline', ['warn', 'pass', 'pass', 'pass', 'pass', 'pass']],
        6: [{ anomaly_score: 0.3, deauth_count: 15, signal_zscore: 0, has_pcap_capture: true }, 'Investigate further', ['warn', 'pass', 'fail', 'pass', 'pass', 'warn']],
        7: [{ anomaly_score: 0.1, has_pcap_capture: true }, 'Dismiss', ['pass', 'pass', 'pass', 'unknown', 'pass', 'pass']],
        8: [{ anomaly_score: undefined, channel: undefined, band: undefined, security: undefined, signal_dbm: undefined },
            'Add to baseline', ['pass', 'pass', 'pass', 'unknown', 'warn', 'pass']],
        // Boundaries: 10 deauth frames fail, 9 warn; a score of 0.7 fails but only escalates above 0.7.
        9: [{ anomaly_score: 0.1, deauth_count: 10, has_pcap_capture: true }, 'Investigate further', ['pass', 'pass', 'fail', 'unknown', 'pass', 'warn']],
        10: [{ anomaly_score: 0.1, deauth_count: 9, has_pcap_capture: true }, 'Add to baseline', ['pass', 'pass', 'warn', 'unknown', 'pass', 'pass']],
        11: [{ anomaly_score: 0.7, signal_zscore: 0, has_pcap_capture: true }, 'Investigate further', ['fail', 'pass', 'pass', 'pass', 'pass', 'warn']],
    };
    const f = panel({ anomalies: Object.entries(cases).map(([id, [extra]]) => anomaly(Number(id), { ssid: '', bssid: '', ...extra })) });
    await f.tick(1500);
    const steps = () => f.el('wifi-inv-checklist').querySelectorAll('.inv-step').map(step => step.className.replace('inv-step inv-', ''));
    const detail = label => f.el('wifi-inv-checklist').querySelectorAll('.inv-step')
        .find(step => step.querySelector('.inv-step-label').textContent === label).querySelector('.inv-step-detail').textContent;
    for (const [id, [, action, statuses]] of Object.entries(cases)) {
        queue(f).querySelector(`[data-wifi-investigate="${id}"]`).click();
        assert.equal(f.el('wifi-inv-recommendation').querySelector('.inv-rec-action').textContent, action, 'case ' + id);
        assert.deepEqual(steps(), statuses, 'case ' + id);
    }
    queue(f).querySelector('[data-wifi-investigate="2"]').click();
    assert.equal(detail('Detection Dimensions'), '2 dimension(s) triggered: New Network, Client Surge');
    assert.equal(detail('Deauth Activity'), '3 deauth frames — could be normal roaming');
    assert.equal(detail('Packet Capture'), 'Frame metadata available but no raw pcap capture');
    assert.equal(detail('Threat Assessment'), 'Multiple warnings — monitor closely');
    queue(f).querySelector('[data-wifi-investigate="3"]').click();
    assert.equal(detail('Packet Capture'), 'Pcap capture available (9 frames) — download for Wireshark analysis');
    assert.equal(detail('Signal Strength Analysis'), 'Signal z-score -3.5 — significant deviation, possible rogue AP');
    assert.equal(detail('Threat Assessment'), 'Multiple critical indicators — potential active attack');
    queue(f).querySelector('[data-wifi-investigate="4"]').click();
    assert.equal(detail('Threat Assessment'), 'One critical indicator — investigate before dismissing');
    assert.equal(detail('Packet Capture'), 'Pcap capture available — download for Wireshark analysis');
    assert.equal(f.el('wifi-investigate-title').textContent, 'WiFi Investigation: Unknown');
    const context = Object.fromEntries(f.el('wifi-inv-context').querySelectorAll('.dd-field')
        .map(field => [field.querySelector('.dd-field-label').textContent, field.querySelector('.dd-field-value').textContent]));
    assert.deepEqual([context.SSID, context.BSSID, context.Clients, context.Frames], ['(hidden)', '--', '--', '--']);
    queue(f).querySelector('[data-wifi-investigate="8"]').click();
    const unknown = Object.fromEntries(f.el('wifi-inv-context').querySelectorAll('.dd-field')
        .map(field => [field.querySelector('.dd-field-label').textContent, field.querySelector('.dd-field-value').textContent]));
    assert.deepEqual([unknown.Channel.trim(), unknown.Security, unknown.Signal, unknown['Anomaly Score']], ['--', 'Unknown', '--', '--']);
    assert.equal(detail('Anomaly Score'), 'Score 0.00 — within normal range');

    const overlay = f.el('wifi-investigate-overlay');
    f.el('wifi-investigate-close').click();
    assert.equal(overlay.style.display, 'none');
    queue(f).querySelector('[data-wifi-investigate="1"]').click();
    f.el('wifi-investigate-close-btn').click();
    assert.equal(overlay.style.display, 'none');
    queue(f).querySelector('[data-wifi-investigate="1"]').click();
    f.el('wifi-investigate-body').click();
    assert.equal(overlay.style.display, '');
    overlay.click();
    assert.equal(overlay.style.display, 'none');
});

test('Wi-Fi bulk selection skips anomalies without an ID and acts on exactly the selected ones', async () => {
    let dismiss = {};
    const f = panel({ anomalies: [anomaly(11), anomaly(null, { ssid: 'no-id' })],
        routes: (url, opts) => (url === '/api/wifi/anomalies/bulk/dismiss' && opts.method === 'PUT' ? dismiss : undefined) });
    await f.tick(1500);
    const all = f.el('wifi-select-all');
    all.checked = true;
    all.dispatchEvent(new f.context.Event('change'));
    assert.equal(f.el('wifi-bulk-count').textContent, '1 selected');
    f.el('wifi-bulk-export').click();
    assert.equal(f.navigations.at(-1), 'open:/api/export/wifi_anomalies?format=json&ids=11');
    assert.equal(f.toasts().at(-1), 'Exporting 1 WiFi anomalies');
    dismiss = NOT_JSON();
    f.el('wifi-bulk-dismiss').click();
    await settle();
    assert.equal(f.dialogs.length, 0, 'one selected anomaly is dismissed without a prompt');
    assert.equal(f.toasts().at(-1), 'Bulk dismiss failed');
    assert.equal(f.el('wifi-bulk-count').textContent, '1 selected', 'a failed dismissal keeps the selection');
    dismiss = {};
    f.el('wifi-bulk-dismiss').click();
    await settle();
    // The server model takes ids: list[int] in lax mode, so a numeric string is accepted as well.
    assert.deepEqual(f.body(f.lastWrite()).ids.map(Number), [11]);
    assert.equal(f.el('wifi-bulk-count').textContent, '0 selected');
    all.checked = true;
    all.dispatchEvent(new f.context.Event('change'));
    all.checked = false;
    all.dispatchEvent(new f.context.Event('change'));
    assert.equal(f.el('wifi-bulk-count').textContent, '0 selected');
    const box = queue(f).querySelector('[data-wifi-bulk-id="11"]');
    box.checked = true;
    box.dispatchEvent(new f.context.Event('change'));
    box.checked = false;
    box.dispatchEvent(new f.context.Event('change'));
    assert.equal(f.el('wifi-bulk-count').textContent, '0 selected');
    assert.ok(!box.closest('.anomaly-card').classList.contains('bulk-selected'));
});

test('a Wi-Fi anomaly without an ID gets a disabled box, and Select all ticks once every anomaly with an ID is selected', async () => {
    const f = panel({ anomalies: [anomaly(11), anomaly(null, { ssid: 'no-id' })] });
    await f.tick(1500);
    const boxes = queue(f).querySelectorAll('.bulk-checkbox');
    assert.deepEqual(boxes.map(box => [box.getAttribute('data-wifi-bulk-id'), box.hasAttribute('disabled')]), [['11', false], [null, true]]);
    const all = f.el('wifi-select-all');
    assert.equal(all.checked, false);
    const box = queue(f).querySelector('[data-wifi-bulk-id="11"]');
    box.checked = true;
    box.dispatchEvent(new f.context.Event('change'));
    assert.deepEqual([all.checked, f.el('wifi-bulk-count').textContent], [true, '1 selected']);
    box.checked = false;
    box.dispatchEvent(new f.context.Event('change'));
    assert.deepEqual([all.checked, f.el('wifi-bulk-count').textContent], [false, '0 selected']);
});

test('the Wi-Fi bulk-action bar hides once the last anomaly is gone', async () => {
    const anomalies = [anomaly(11), anomaly(12)];
    const f = panel({ anomalies });
    await f.tick(1500);
    const all = f.el('wifi-select-all');
    all.checked = true;
    all.dispatchEvent(new f.context.Event('change'));
    anomalies.length = 0;
    f.answerConfirm(true);
    f.el('wifi-bulk-dismiss').click();
    await settle();
    assert.equal(f.el('wifi-anomaly-empty').style.display, '');
    assert.equal(f.el('wifi-bulk-bar').style.display, 'none');
});
