/* The shipped Wi-Fi SIGINT panel (wifi.js) inside the real dashboard boot.
 * SSIDs, vendor names and frame metadata come from radios anyone in range
 * controls, so every one of them must stay text. */
const assert = require('node:assert/strict');
const test = require('node:test');
const { bootDashboard, response, injected, settle, idsNamed } = require('./untrusted_dom.cjs');

const MARKUP = '<img src=x onerror=alert(1)><script>alert(2)</script>';
const QUOTE = 'x" onmouseover="alert(3)" data-x="';
const CSRF = 'csrf-abc123';
const AP = '02:00:00:00:00:01', CORP = '02:00:00:00:00:02';
const IDS = ['tbody:wifi-network-tbody', 'wifi-network-empty', 'wifi-net-count-badge', 'wifi-client-list', 'wifi-client-empty',
    'canvas:wifi-signal-canvas', 'wifi-anomaly-queue', 'wifi-anomaly-empty', 'wifi-anomaly-count-badge', 'sum-wifi-anomalies',
    'select:wifi-anomaly-group-select', 'select:wifi-anomaly-filter-key', 'select:wifi-anomaly-filter-val',
    'wifi-investigate-overlay', 'wifi-investigate-title', 'wifi-inv-context', 'wifi-inv-checklist', 'wifi-inv-recommendation',
    'select:wifi-net-group-select', 'select:wifi-net-show-select', 'wifi-reeval-summary', 'wifi-bulk-bar', 'wifi-bulk-count',
    'input:wifi-select-all', 'button:wifi-bulk-dismiss', 'button:wifi-bulk-escalate', 'button:wifi-bulk-export'];

const now = () => new Date().toISOString();
const network = (bssid, ssid, extra = {}) => ({ bssid, ssid, vendor: 'V', channel: 6, band: '2.4GHz', security: 'WPA2',
    avg_signal_dbm: -60, client_count: 1, last_seen: now(), ...extra });
const anomaly = (id, extra = {}) => ({ id, ssid: 'net-' + id, bssid: AP, channel: 6, band: '2.4GHz', security: 'WPA2',
    signal_dbm: -50, anomaly_score: 0.8, timestamp: now(), ...extra });

function panel({ networks = [], anomalies = [], routes = () => undefined, ...options } = {}) {
    const f = bootDashboard({ ids: IDS, scripts: ['wifi.js'], ...options, routes: (url, opts, call) => {
        const answer = routes(url, opts, call);
        if (answer !== undefined) return answer;
        if (opts.method && opts.method !== 'GET') return {};
        if (url.startsWith('/api/admin/wifi-whitelist')) return { whitelist: [{ bssid: CORP.toLowerCase(), id: 1 }] };
        if (url.startsWith('/api/wifi/networks')) return { networks };
        if (url.startsWith('/api/wifi/anomalies?min_score=0.3')) return { anomalies, total: anomalies.length };
        if (url.startsWith('/api/wifi/clients')) return { clients: [{ client_mac: '<b>aa</b>', ssid: MARKUP, avg_signal_dbm: -40, avg_data_rate: 54, frame_count: 3, last_seen: now() }] };
        if (url.startsWith('/api/wifi/timeline')) return { timeline: [] };
        if (url.startsWith('/api/wifi/channels')) return { channels: [] };
        return undefined;
    } });
    f.wifi = f.db.wifiPanel;
    f.wifi.activate();
    return f;
}
// The panel staggers its first loads 0.5-1.5 s after activation (channels,
// stats, anomalies); its 8 s refresh has not run yet.
const loadAnomalies = f => f.tick(2000);
const change = (f, el, value) => { el.value = value; el.dispatchEvent(new f.context.Event('change')); };
const rows = f => f.el('wifi-network-tbody').querySelectorAll('.wifi-net-row');

test('network rows show SSIDs and vendors as text and whitelist exactly the AP the operator confirmed', async () => {
    const f = panel({ networks: [network(AP, MARKUP, { vendor: '<b>Acme</b>', avg_signal_dbm: -40 }), network(CORP, 'Corp', { avg_signal_dbm: -80 })] });
    await settle();
    const tbody = f.el('wifi-network-tbody');
    assert.equal(rows(f).length, 2);
    const cells = rows(f)[0].querySelectorAll('td');
    assert.equal(cells[0].textContent, MARKUP);
    assert.equal(cells[2].textContent, '<b>Acme</b>');
    assert.equal(rows(f)[1].querySelector('.admin-badge').textContent, 'Authorized');
    assert.equal(f.el('wifi-net-count-badge').textContent, '2');
    assert.deepEqual(injected(tbody), []);

    const button = tbody.querySelector('[data-wl-bssid]');
    assert.equal(button.getAttribute('data-wl-ssid'), MARKUP);
    f.answerConfirm(false);
    button.click();
    assert.equal(f.writes().length, 0);
    assert.ok(f.dialogs.at(-1)[1].includes(AP + ' (' + MARKUP + ')'));
    f.answerConfirm(true);
    button.click();
    await settle();
    assert.equal(f.lastWrite().url, '/api/admin/wifi-whitelist');
    assert.equal(f.lastWrite().headers['X-CSRF-Token'], CSRF);
    assert.deepEqual(f.body(f.lastWrite()), { bssid: AP, ssid: MARKUP });
    assert.ok(f.toasts().includes('Whitelisted ' + MARKUP));

    rows(f)[0].querySelectorAll('td')[1].click();
    await settle();
    assert.ok(f.requests.some(call => call.url.startsWith('/api/wifi/clients?bssid=' + encodeURIComponent(AP))));
    const clients = f.el('wifi-client-list');
    assert.equal(clients.querySelectorAll('td')[1].textContent, MARKUP);
    assert.equal(clients.querySelector('code').textContent, '<b>aa</b>');
    assert.deepEqual(injected(clients), []);
});

test('grouping and authorization filters keep SSID labels literal', async () => {
    const f = panel({ networks: [network(AP, MARKUP), network('02:00:00:00:00:03', MARKUP), network(CORP, 'Corp')] });
    await settle();
    change(f, f.el('wifi-net-group-select'), 'ssid');
    const headers = () => f.el('wifi-network-tbody').querySelectorAll('.wifi-net-group-header');
    assert.equal(headers()[0].getAttribute('data-net-group'), MARKUP);
    assert.ok(headers()[0].textContent.includes('Ssid: ' + MARKUP + ' (2)'));
    assert.deepEqual(injected(f.el('wifi-network-tbody')), []);
    headers()[0].click();
    assert.equal(rows(f).length, 1, 'the collapsed group hides its rows');
    change(f, f.el('wifi-net-group-select'), '');
    change(f, f.el('wifi-net-show-select'), 'authorized');
    assert.deepEqual(rows(f).map(row => row.getAttribute('data-bssid')), [CORP]);
    change(f, f.el('wifi-net-show-select'), 'unauthorized');
    assert.equal(rows(f).length, 2);
});

test('a raw SSID with a quote cannot break out of the Whitelist button attributes', async () => {
    const f = panel({ networks: [network(AP, QUOTE)], anomalies: [anomaly(1, { ssid: QUOTE })] });
    await loadAnomalies(f);
    assert.deepEqual(injected(f.el('wifi-network-tbody')), []);
    assert.deepEqual(injected(f.el('wifi-anomaly-queue')), []);
});

test('Wi-Fi anomaly cards render radio-supplied strings as text and act on the exact anomaly', async () => {
    const a = anomaly(11, { ssid: MARKUP, vendor: '<b>v</b>', channel: '<i>6</i>', security: '<u>WEP</u>', baseline_status: '<s>x</s>',
        reasons: [MARKUP], dimensions: { evil_twin: 0.9, [MARKUP]: 0.3 }, frame_type_counts: { beacon: 3, [MARKUP]: 1 },
        frame_count: 4, deauth_count: 2, has_pcap_capture: true, pcap_frame_count: 4, client_count: 1 });
    const f = panel({ anomalies: [a], routes: (url, options) => {
        if (url.startsWith('/api/wifi/anomalies/11/reevaluate')) return { still_anomalous: false, score_delta: -0.2, new_score: 0.3,
            original_score: 0.5, baseline_status: '<b>b</b>', baseline_observations: 3, new_reasons: [MARKUP] };
        if (url.startsWith('/api/wifi/anomalies/11/pcap/summary')) return { total_frames: 2, duration_ms: 5, size_bytes: 2048,
            frame_types: { [MARKUP]: 1, beacon: 1 }, frames: [{ frame_type: MARKUP, length: '<b>9</b>' }] };
        if (url.startsWith('/api/wifi/anomalies?include_frames=true')) return { anomalies: [{ id: 11,
            frame_capture: [{ frame_type: MARKUP, client_mac: 'aa:bb:cc:dd:ee:ff', signal_dbm: -40, data_rate_mbps: '<b>1</b>', retry_flag: 0 }] }] };
        return options.method && options.method !== 'GET' ? {} : undefined;
    } });
    await loadAnomalies(f);
    const queue = f.el('wifi-anomaly-queue');
    const card = queue.querySelector('.anomaly-card');
    assert.equal(card.querySelector('strong').textContent, MARKUP);
    assert.equal(card.querySelector('.anomaly-reasons small').textContent, MARKUP);
    assert.deepEqual(card.querySelectorAll('.dim-tag').map(tag => tag.textContent), ['Evil Twin: 0.90', MARKUP + ': 0.30']);
    assert.ok(card.querySelectorAll('.frame-type-bar div').some(bar => bar.getAttribute('title') === MARKUP + ': 1'));
    for (const text of ['Vendor: <b>v</b>', 'Ch <i>6</i>', '<u>WEP</u>', '<s>x</s>', 'Deauth: 2']) assert.ok(card.textContent.includes(text), text);
    assert.equal(card.querySelector('.btn-pcap').getAttribute('href'), '/api/wifi/anomalies/11/pcap');
    assert.equal(f.el('wifi-anomaly-count-badge').textContent, '1');
    assert.deepEqual(injected(queue), []);

    card.querySelector('[data-wifi-dismiss]').click();
    await settle();
    assert.equal(f.lastWrite().url, '/api/wifi/anomalies/11/dismiss');
    assert.equal(f.lastWrite().method, 'PUT');
    assert.equal(f.lastWrite().headers['X-CSRF-Token'], CSRF);
    card.querySelector('[data-wifi-reeval]').click();
    await settle();
    const result = f.el('wifi-reeval-11');
    assert.ok(result.textContent.includes('Now Normal') && result.textContent.includes('Baseline: <b>b</b>'));
    assert.ok(result.textContent.includes('Reasons: ' + MARKUP));
    card.querySelector('[data-pcap-summary]').click();
    await settle();
    const summary = f.el('pcap-summary-11');
    assert.ok(summary.querySelector('.pcap-ft-legend').textContent.includes(MARKUP + ': 1'));
    assert.equal(summary.querySelectorAll('tbody td')[1].textContent, MARKUP);
    card.querySelector('[data-wifi-frames]').click();
    await settle();
    const frames = f.el('pcap-wrap-11').querySelector('.pcap-content');
    assert.equal(frames.querySelector('tbody td').textContent, MARKUP);
    assert.equal(frames.querySelector('code').textContent, '...ee:ff');
    for (const el of [result, summary, frames]) assert.deepEqual(injected(el), []);

    card.querySelector('[data-wifi-investigate]').click();
    assert.equal(f.el('wifi-investigate-overlay').style.display, '');
    assert.equal(f.el('wifi-investigate-title').textContent, 'WiFi Investigation: ' + MARKUP);
    assert.ok(f.el('wifi-inv-context').textContent.includes('SSID' + MARKUP));
    assert.deepEqual(injected(f.el('wifi-inv-context')), []);
    assert.deepEqual(injected(f.el('wifi-inv-checklist')), []);
});

test('grouped Wi-Fi anomalies use exact IDs for bulk actions and literal labels', async () => {
    const f = panel({ anomalies: [anomaly(11, { ssid: MARKUP, security: '<b>Open</b>' }), anomaly(12, { ssid: MARKUP, anomaly_score: 0.6 }),
        anomaly(13, { ssid: 'other', anomaly_score: 0.4 })], routes: url => url.startsWith('/api/wifi/anomalies/bulk/reevaluate')
        ? { results: { 11: { still_anomalous: true, score_delta: 0.1, new_score: 0.9 } } } : undefined });
    await loadAnomalies(f);
    change(f, f.el('wifi-anomaly-group-select'), 'ssid');
    assert.equal(f.el('wifi-anomaly-group-select').value, 'ssid', 'the page offers this grouping');
    const queue = f.el('wifi-anomaly-queue');
    const group = queue.querySelector('.wifi-mac-group');
    assert.equal(group.querySelector('strong').textContent, 'ssid: ' + MARKUP);
    assert.match(group.querySelector('[data-wifi-mac-toggle]').getAttribute('data-wifi-mac-toggle'), /^wifi-grp-[A-Za-z0-9_-]+$/);
    assert.deepEqual(injected(queue), []);
    group.querySelector('[data-wifi-mac-toggle]').click();
    assert.equal(group.querySelector('.wifi-mac-group-items').style.display, '');
    // Dismissing a whole group asks first; a cancelled prompt sends nothing.
    f.answerConfirm(false);
    group.querySelector('[data-wifi-dismiss-bulk]').click();
    assert.equal(f.writes().length, 0);
    assert.equal(f.dialogs.at(-1)[1], 'Dismiss 2 WiFi anomalies?');
    f.answerConfirm(true);
    group.querySelector('[data-wifi-dismiss-bulk]').click();
    await settle();
    assert.equal(f.lastWrite().url, '/api/wifi/anomalies/bulk/dismiss');
    assert.deepEqual(f.body(f.lastWrite()), { ids: [11, 12] });
    group.querySelector('[data-wifi-reeval-bulk]').click();
    await settle();
    assert.deepEqual(f.body(f.lastWrite()), { ids: [11, 12] });
    assert.ok(f.el('wifi-reeval-11').textContent.includes('Still Anomalous'));

    change(f, f.el('wifi-anomaly-group-select'), '');
    change(f, f.el('wifi-anomaly-filter-key'), 'ssid');
    const filter = f.el('wifi-anomaly-filter-val');
    assert.deepEqual(filter.options.map(option => [option.value, option.textContent]), [['', 'All'], [MARKUP, MARKUP], ['other', 'other']]);
    assert.deepEqual(injected(filter), []);
    change(f, filter, MARKUP);
    assert.equal(filter.value, MARKUP);
    const shownIds = () => queue.querySelectorAll('[data-wifi-bulk-id]').map(box => box.getAttribute('data-wifi-bulk-id')).sort();
    assert.deepEqual(shownIds(), ['11', '12']);

    // Selected anomalies are dismissed by their exact IDs, after confirmation.
    change(f, f.el('wifi-anomaly-filter-key'), '');
    assert.deepEqual(shownIds(), ['11', '12', '13']);
    for (const box of queue.querySelectorAll('[data-wifi-bulk-id]').filter(box => box.getAttribute('data-wifi-bulk-id') !== '12')) {
        box.checked = true;
        box.dispatchEvent(new f.context.Event('change'));
    }
    assert.equal(f.el('wifi-bulk-count').textContent, '2 selected');
    const count = f.writes().length;
    f.answerConfirm(false);
    f.el('wifi-bulk-dismiss').click();
    f.el('wifi-bulk-escalate').click();
    assert.equal(f.writes().length, count, 'a cancelled dismissal or escalation sends nothing');
    assert.deepEqual(f.dialogs.slice(-2).map(([, message]) => message.split('?')[0]),
        ['Dismiss 2 selected WiFi anomalies', 'Escalate 2 selected WiFi anomalies']);
    f.answerConfirm(true);
    f.el('wifi-bulk-dismiss').click();
    await settle();
    assert.equal(f.lastWrite().url, '/api/wifi/anomalies/bulk/dismiss');
    assert.equal(f.lastWrite().headers['X-CSRF-Token'], CSRF);
    assert.deepEqual(f.body(f.lastWrite()).ids.sort(), ['11', '13']);
});

test('live Wi-Fi frames: malformed ones are ignored and only an active panel refreshes', async () => {
    // A held token: its socket carries the credential in the subprotocol.
    const f = panel({ cookie: '', token: 'tok-' + 'W'.repeat(40) });
    await settle();
    const socket = f.sockets.find(s => s.url === 'wss://bridge.test/api/wifi/ws/wifi');
    assert.ok(socket);
    socket.open();
    const polls = () => f.requests.filter(call => /^\/api\/wifi\/(networks|stats|anomalies\?)/.test(call.url)).length;
    let count = polls();
    for (const frame of ['garbage', 'null', '{"type":"other"}', '[]']) assert.doesNotThrow(() => socket.message(frame));
    assert.equal(polls(), count);
    socket.message({ type: 'wifi_ingest' });
    socket.message({ type: 'wifi_anomaly' });
    assert.equal(polls(), count + 3);
    f.wifi.deactivate();
    count = polls();
    socket.message({ type: 'wifi_ingest' });
    assert.equal(polls(), count, 'an inactive panel ignores live frames');
});

test('a cookie session also receives live Wi-Fi updates', async () => {
    const f = panel();
    await settle();
    assert.ok(f.sockets.some(s => s.url === 'wss://bridge.test/api/wifi/ws/wifi'));
});

test('pcap download and export links never put the API key in a URL', async () => {
    const key = 'key-' + 'P'.repeat(40);
    const f = panel({ cookie: '', apiKey: key, anomalies: [anomaly(11, { has_pcap_capture: true, frame_count: 1 })] });
    await loadAnomalies(f);
    assert.ok(!f.el('wifi-anomaly-queue').querySelector('.btn-pcap').getAttribute('href').includes(key));
    const all = f.el('wifi-select-all');
    all.checked = true;
    all.dispatchEvent(new f.context.Event('change'));
    f.el('wifi-bulk-export').click();
    const opened = f.navigations.filter(url => url.startsWith('open:'));
    assert.equal(opened.length, 1);
    assert.ok(!opened[0].includes(key), opened[0]);
});

test('escalating selected Wi-Fi anomalies does not dismiss them', async () => {
    const f = panel({ anomalies: [anomaly(11), anomaly(12)] });
    await loadAnomalies(f);
    const all = f.el('wifi-select-all');
    all.checked = true;
    all.dispatchEvent(new f.context.Event('change'));
    f.answerConfirm(true);
    const before = f.writes().length;
    f.el('wifi-bulk-escalate').click();
    await settle();
    // The escalation is sent, names every selected anomaly, and dismisses none.
    const sent = f.writes().slice(before);
    assert.ok(sent.length, 'escalation was requested');
    for (const call of sent) assert.doesNotMatch(call.url, /dismiss/, call.url);
    const named = idsNamed(sent);
    for (const id of ['11', '12']) assert.ok(named.has(id), [...named].join(' '));
});

test('a Wi-Fi escalation raises an alert through the escalation endpoint and says what it did, or why it failed', async () => {
    let answer = { ok: true, alert_id: 'alert_1', escalated_count: 2, escalated: [11, 12], already_escalated: [], not_found: [] };
    const f = panel({ anomalies: [anomaly(11), anomaly(12)],
        routes: (url, opts) => (opts.method === 'POST' && url === '/api/wifi/anomalies/bulk/escalate' ? answer : undefined) });
    await loadAnomalies(f);
    const selectAll = () => {
        const all = f.el('wifi-select-all');
        all.checked = true;
        all.dispatchEvent(new f.context.Event('change'));
    };
    selectAll();
    f.answerConfirm(true);
    f.el('wifi-bulk-escalate').click();
    await settle();
    const write = f.lastWrite();
    assert.deepEqual([write.method, write.url, write.headers['X-CSRF-Token']], ['POST', '/api/wifi/anomalies/bulk/escalate', CSRF]);
    assert.deepEqual(f.body(write).ids.sort(), ['11', '12']);
    assert.equal(f.dialogs.at(-1)[1], 'Escalate 2 selected WiFi anomalies? One critical alert names them; none is dismissed.');
    assert.equal(f.toasts().at(-1), 'Critical alert raised for 2 anomalies');
    assert.equal(f.el('wifi-bulk-count').textContent, '0 selected');
    assert.deepEqual(f.el('wifi-anomaly-queue').querySelectorAll('[data-wifi-bulk-id]').map(box => box.getAttribute('data-wifi-bulk-id')).sort(),
        ['11', '12'], 'the escalated anomalies stay in the queue');

    answer = response(422, { detail: 'ids must contain at most 100 items' });
    selectAll();
    f.el('wifi-bulk-escalate').click();
    await settle();
    assert.equal(f.toasts().at(-1), 'Bulk escalation failed: ids must contain at most 100 items');
});

test('a Wi-Fi escalation naming more anomalies than the server accepts is not sent', async () => {
    const f = panel({ anomalies: Array.from({ length: 101 }, (_, i) => anomaly(i + 1)) });
    await loadAnomalies(f);
    const all = f.el('wifi-select-all');
    all.checked = true;
    all.dispatchEvent(new f.context.Event('change'));
    f.answerConfirm(true);
    const writes = f.writes().length, dialogs = f.dialogs.length;
    f.el('wifi-bulk-escalate').click();
    await settle();
    assert.equal(f.writes().length, writes, 'nothing is sent');
    assert.equal(f.dialogs.length, dialogs, 'nothing is asked');
    assert.equal(f.toasts().at(-1), 'Escalate at most 100 anomalies at a time (101 selected)');
    assert.equal(f.el('wifi-bulk-count').textContent, '101 selected', 'the selection is kept');
});

test('pcap download and export links are the exact key-free paths', async () => {
    const key = 'key-' + 'P'.repeat(40);
    const f = panel({ cookie: '', apiKey: key, anomalies: [anomaly(11, { has_pcap_capture: true, frame_count: 1 }), anomaly(12)] });
    await loadAnomalies(f);
    assert.equal(f.el('wifi-anomaly-queue').querySelector('.btn-pcap').getAttribute('href'), '/api/wifi/anomalies/11/pcap');
    const all = f.el('wifi-select-all');
    all.checked = true;
    all.dispatchEvent(new f.context.Event('change'));
    f.el('wifi-bulk-export').click();
    const [opened] = f.navigations.filter(url => url.startsWith('open:'));
    assert.match(opened, /^open:\/api\/export\/wifi_anomalies\?format=json&ids=(11,12|12,11)$/);
});

test('a cookie session also receives live Bluetooth updates; no session opens no socket', async () => {
    const f = bootDashboard({ scripts: ['bluetooth.js'] });
    await settle();
    const socket = f.sockets.find(s => s.url === 'wss://bridge.test/api/bluetooth/ws/bluetooth');
    assert.ok(socket, f.sockets.map(s => s.url).join(' '));
    assert.deepEqual([...socket.protocols], [], 'the HttpOnly session cookie authenticates the upgrade');
    const none = bootDashboard({ cookie: '', scripts: ['bluetooth.js'] });
    await settle();
    assert.deepEqual(none.sockets, []);
});
