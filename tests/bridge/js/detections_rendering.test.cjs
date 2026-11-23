/* The shipped RF Intelligence panel (detections.js) inside the real dashboard
 * boot: sensor-supplied detection fields, live frames and analyst actions. */
const assert = require('node:assert/strict');
const test = require('node:test');
const { bootDashboard, response, injected, settle, idsNamed } = require('./untrusted_dom.cjs');

const MARKUP = '<img src=x onerror=alert(1)><script>alert(2)</script>';
const QUOTE = 'x" onmouseover="alert(3)" data-x="';
const CSRF = 'csrf-abc123';
const IDS = ['tbody:det-feed-tbody', 'det-feed-empty', 'det-count-badge', 'anomaly-queue', 'anomaly-empty',
    'anomaly-count-badge', 'stat-anomaly-detail', 'select:rf-anomaly-group-select', 'select:rf-anomaly-filter-key',
    'select:rf-anomaly-filter-val', 'rf-bulk-bar', 'rf-bulk-count', 'input:rf-select-all', 'button:rf-bulk-dismiss',
    'button:rf-bulk-escalate', 'button:rf-bulk-export', 'deep-dive-overlay', 'deep-dive-title', 'dd-context', 'dd-baseline',
    'button:dd-download-iq', 'button:dd-export', 'button:dd-mark-known', 'dd-feedback-group', 'dd-investigation-checklist',
    'dd-investigation-recommendation', 'button:deep-dive-close', 'tbody:iq-captures-tbody', 'iq-captures-empty',
    'iq-commands-list', 'select:iq-filter-node', 'select:iq-filter-class', 'button:det-pause-btn', 'button:dd-capture-iq',
    'iq-capture-overlay', 'select:iq-capture-node-id', 'input:iq-capture-freq', 'input:iq-capture-duration',
    'input:iq-capture-samplerate', 'input:iq-capture-gain', 'iq-capture-status', 'button:iq-capture-submit'];
// The panel staggers its first loads 1-4 s after activation (charts,
// anomalies, summary, IQ inventory); its 8 s refresh has not run yet.
const FIRST_LOADS_MS = 5000;

function panel({ feed = [], anomalies = [], routes = () => undefined, ...options } = {}) {
    const f = bootDashboard({ ids: IDS, scripts: ['chart_utils.js', 'detections.js'], ...options, routes: (url, opts, call) => {
        const answer = routes(url, opts, call);
        if (answer !== undefined) return answer;
        if (url.startsWith('/api/detections/recent')) return { count: feed.length, detections: feed };
        if (url.startsWith('/api/detections/anomalies?')) return { anomalies, total: anomalies.length };
        if (url.startsWith('/api/detections/stats')) return { active_frequencies: 1 };
        return opts.method && opts.method !== 'GET' ? {} : undefined;
    } });
    f.dd = f.db.detectionDashboard;
    f.dd.activate();
    f.known = [];
    f.context.KnownSignals = { open: (db, id) => f.known.push(id), bind() {} };
    return f;
}
const cards = f => f.el('anomaly-queue').querySelectorAll('.anomaly-card');
const change = (f, el, value) => { el.value = value; el.dispatchEvent(new f.context.Event('change')); };
// Let the first loads run, with the anomaly queue optionally grouped.
async function loadAnomalies(f, groupBy) {
    if (groupBy) change(f, f.el('rf-anomaly-group-select'), groupBy);
    assert.equal(f.el('rf-anomaly-group-select').value, groupBy || '', 'the page offers this grouping');
    await f.tick(FIRST_LOADS_MS);
}

test('the detection feed groups sensor detections, renders their strings as text and opens a deep dive', async () => {
    const feed = [
        { detection_id: 'd-1', signal_class: 'lora<b>', freq_hz: 433920000, node_id: MARKUP, confidence: 0.9,
            snr_db: 12, baseline_status: 'learning', anomaly_score: 0.8 },
        { detection_id: 'd-2', signal_class: 'lora<b>', freq_hz: 433920000, node_id: 'edge-2', confidence: 0.7 },
        { detection_id: 'd-3', signal_class: 'fm', freq_hz: 100e6, node_id: 'edge-3' }];
    const f = panel({ feed });
    await settle();
    const tbody = f.el('det-feed-tbody');
    const rows = tbody.querySelectorAll('.det-feed-row');
    assert.equal(rows.length, 2);
    assert.equal(f.el('det-count-badge').textContent, '3');
    assert.equal(rows[0].getAttribute('data-dd-class'), 'lora<b>');
    assert.equal(rows[0].querySelectorAll('td')[2].textContent, MARKUP + ', edge-2');
    assert.equal(rows[0].querySelector('.baseline-badge').textContent, 'learning');
    assert.deepEqual(injected(tbody), []);

    const overlay = f.el('deep-dive-overlay');
    overlay.style.display = 'none';
    rows[0].querySelector('[data-drilldown-class]').click();
    assert.equal(overlay.style.display, 'none', 'a drill-down link does not open the deep dive');
    rows[0].querySelectorAll('td')[3].click();
    await settle();
    assert.equal(overlay.style.display, '');
    assert.equal(f.el('deep-dive-title').textContent, 'Deep-Dive: lora<b>');
    assert.ok(f.el('dd-context').textContent.includes('Node' + MARKUP));
    assert.deepEqual(injected(f.el('dd-context')), []);
    assert.deepEqual(injected(f.el('dd-investigation-checklist')), []);
});

test('live detection frames: malformed ones are ignored, hostile ones render only as text', async () => {
    const anomaly = { id: 1, detection_id: 'd-9', signal_class: 'dmr', anomaly_score: 0.9, timestamp: new Date().toISOString() };
    const f = panel({ anomalies: [anomaly] });
    await loadAnomalies(f, 'signal_class');
    const socket = f.sockets.find(s => s.url === 'wss://bridge.test/api/detections/ws/feed');
    assert.ok(socket, 'the panel subscribes to the live feed');
    socket.open();
    const shown = () => f.el('det-count-badge').textContent;
    const groups = () => cards(f).map(card => card.querySelector('strong').textContent).sort();
    assert.equal(shown(), '0');
    assert.deepEqual(groups(), ['dmr']);
    for (const frame of ['garbage', '{"type":"detection"}', '{"type":"anomaly"}', 'null', '{"type":"iq_available"}']) {
        assert.doesNotThrow(() => socket.message(frame));
    }
    // One real detection after the malformed frames: the debounced render shows exactly one.
    socket.message({ type: 'detection', detection: { signal_class: 'x<y>', node_id: MARKUP, freq_band: '1.00 MHz' } });
    await f.tick(1000);
    assert.equal(shown(), '1');
    assert.ok(f.el('det-feed-tbody').textContent.includes(MARKUP));
    assert.deepEqual(groups(), ['dmr'], 'malformed anomaly frames add nothing');
    socket.message({ type: 'anomaly', anomaly: { id: 2, signal_class: 'p25', node_id: MARKUP, anomaly_score: 0.95, reasons: [MARKUP] } });
    assert.deepEqual(groups(), ['dmr', 'p25']);
    assert.ok(f.el('anomaly-queue').textContent.includes('Nodes: ' + MARKUP));
    assert.equal(f.el('anomaly-queue').querySelectorAll('.iq-badge').length, 0);
    socket.message({ type: 'iq_available', detection_id: 'd-9' });
    assert.equal(f.el('anomaly-queue').querySelectorAll('.iq-badge').length, 1);
    // Pause freezes the panel; Resume takes live frames again.
    const pause = f.el('det-pause-btn');
    pause.click();
    assert.equal(pause.textContent, 'Resume');
    socket.message({ type: 'anomaly', anomaly: { id: 3, signal_class: 'tetra', anomaly_score: 0.9 } });
    socket.message({ type: 'detection', detection: { signal_class: 'tetra', node_id: 'edge-1' } });
    await f.tick(1000);
    assert.deepEqual(groups(), ['dmr', 'p25'], 'a paused panel ignores live anomalies');
    assert.equal(shown(), '1', 'a paused panel ignores live detections');
    pause.click();
    assert.equal(pause.textContent, 'Pause');
    socket.message({ type: 'anomaly', anomaly: { id: 4, signal_class: 'nxdn', anomaly_score: 0.9 } });
    assert.deepEqual(groups(), ['dmr', 'nxdn', 'p25']);
    assert.deepEqual(injected(f.document.body), []);
});

test('the default RF anomaly queue renders its cards and acts on the exact anomaly', async () => {
    const now = new Date().toISOString();
    const anomalies = [
        { id: 7, detection_id: 'det/7', signal_class: 'dmr', family: MARKUP, node_id: MARKUP, anomaly_score: 0.9,
            reasons: [MARKUP], dimensions: { [MARKUP]: 0.5, spectral: 0.2 }, freq_hz: 446e6, baseline_status: '<b>drift</b>',
            seen_count: 3, timestamp: now, has_iq_capture: true },
        { id: 8, detection_id: 'det-8', signal_class: 'fm', node_id: 'edge-2', anomaly_score: 0.55, timestamp: now },
        { id: 9, detection_id: 'det-9', signal_class: 'fm', node_id: 'edge-3', anomaly_score: 0.35, timestamp: now }];
    const f = panel({ anomalies });
    await loadAnomalies(f);
    const queue = f.el('anomaly-queue');
    assert.equal(cards(f).length, 3);
    assert.deepEqual(queue.querySelectorAll('.section-count').map(el => el.textContent), ['(1)', '(1)', '(1)']);
    const first = cards(f)[0];
    assert.equal(first.querySelector('.reason-tag').textContent, MARKUP);
    assert.equal(first.querySelector('.dim-tag').textContent, MARKUP + ': 0.50');
    assert.ok(first.textContent.includes('Node: ' + MARKUP));
    assert.equal(first.querySelector('.baseline-badge').textContent, '<b>drift</b>');
    assert.deepEqual(injected(queue), []);

    first.querySelector('[data-dismiss-rf]').click();
    first.querySelector('[data-baseline-anomaly]').click();
    await settle();
    assert.equal(f.lastWrite().url, '/api/detections/anomalies/7/dismiss');
    assert.equal(f.lastWrite().method, 'PUT');
    assert.equal(f.lastWrite().headers['X-CSRF-Token'], CSRF);
    assert.deepEqual(f.known, ['det/7']);
    first.querySelector('[data-investigate-idx]').click();
    await settle();
    assert.equal(f.el('deep-dive-title').textContent, 'Deep-Dive: dmr');
    assert.ok(f.requests.some(call => call.url.startsWith('/api/detections/det%2F7/iq?format=json')), 'IQ is fetched for the exact detection');

    // Selecting anomalies dismisses exactly those IDs after confirmation.
    for (const box of queue.querySelectorAll('[data-rf-bulk-id]').slice(0, 2)) {
        box.checked = true;
        box.dispatchEvent(new f.context.Event('change'));
    }
    assert.equal(f.el('rf-bulk-count').textContent, '2 selected');
    const count = f.writes().length;
    f.answerConfirm(false);
    f.el('rf-bulk-dismiss').click();
    assert.equal(f.writes().length, count, 'nothing is dismissed without confirmation');
    f.answerConfirm(true);
    f.el('rf-bulk-dismiss').click();
    await settle();
    assert.equal(f.lastWrite().url, '/api/detections/anomalies/bulk/dismiss');
    assert.deepEqual(f.body(f.lastWrite()), { ids: ['7', '8'] });
});

test('grouping and filtering anomalies use the exact stored values', async () => {
    const now = new Date().toISOString();
    const anomalies = [
        { id: 1, detection_id: 'a', signal_class: 'dmr', node_id: 'edge-<b>1</b>', anomaly_score: 0.9, timestamp: now },
        { id: 2, detection_id: 'b', signal_class: 'dmr', node_id: 'edge-<b>1</b>', anomaly_score: 0.6, timestamp: now },
        { id: 3, detection_id: 'c', signal_class: 'fm', node_id: 'edge-2', anomaly_score: 0.4, timestamp: now }];
    const f = panel({ anomalies });
    await loadAnomalies(f, 'node_id');
    const groups = cards(f);
    assert.deepEqual(groups.map(card => card.querySelector('strong').textContent), ['edge-<b>1</b>', 'edge-2']);
    assert.equal(groups[0].querySelector('[data-rf-bulk-group]').getAttribute('aria-label'), 'Select edge-<b>1</b> group');
    assert.deepEqual(injected(f.el('anomaly-queue')), []);
    f.answerConfirm(false);
    groups[0].querySelector('[data-dismiss-group]').click();
    await settle();
    assert.equal(f.writes().length, 0, 'a group is dismissed only after confirmation');
    f.answerConfirm(true);
    groups[0].querySelector('[data-dismiss-group]').click();
    await settle();
    assert.equal(f.lastWrite().url, '/api/detections/anomalies/bulk/dismiss');
    assert.deepEqual(f.body(f.lastWrite()), { ids: [1, 2] });
    groups[0].querySelector('[data-baseline-group]').click();
    assert.deepEqual(f.known, ['a'], 'a group is reviewed through one exact member');

    change(f, f.el('rf-anomaly-filter-key'), 'node_id');
    const values = f.el('rf-anomaly-filter-val').options.map(option => option.value);
    assert.deepEqual(values, ['', 'edge-2', 'edge-<b>1</b>']);
    assert.deepEqual(f.el('rf-anomaly-filter-val').options.slice(1).map(option => option.textContent), ['edge-2', 'edge-<b>1</b>']);
    change(f, f.el('rf-anomaly-filter-val'), 'edge-2');
    assert.equal(cards(f).length, 1);
    assert.equal(f.el('anomaly-count-badge').textContent, '1 / 3');

    // Selecting a group selects exactly its members; bulk dismissal confirms first.
    change(f, f.el('rf-anomaly-filter-val'), 'edge-<b>1</b>');
    const box = cards(f)[0].querySelector('[data-rf-bulk-group]');
    box.checked = true;
    box.dispatchEvent(new f.context.Event('change'));
    assert.equal(f.el('rf-bulk-count').textContent, '2 selected');
    const count = f.writes().length;
    f.answerConfirm(false);
    f.el('rf-bulk-dismiss').click();
    f.el('rf-bulk-escalate').click();
    assert.equal(f.writes().length, count, 'a cancelled dismissal or escalation sends nothing');
    assert.deepEqual(f.dialogs.slice(-2).map(([, message]) => message.split('?')[0]),
        ['Dismiss 2 selected anomalies', 'Escalate 2 selected anomalies']);
    f.answerConfirm(true);
    f.el('rf-bulk-dismiss').click();
    await settle();
    assert.equal(f.lastWrite().url, '/api/detections/anomalies/bulk/dismiss');
    assert.deepEqual(f.body(f.lastWrite()), { ids: ['1', '2'] });
    // The refreshed queue keeps the active filter, still as literal text.
    const filter = f.el('rf-anomaly-filter-val');
    assert.deepEqual(filter.options.map(option => option.value), ['', 'edge-2', 'edge-<b>1</b>']);
    assert.deepEqual(filter.options.map(option => option.textContent), ['All', 'edge-2', 'edge-<b>1</b>']);
    assert.equal(filter.options.find(option => option.hasAttribute('selected')).value, 'edge-<b>1</b>');
    assert.deepEqual(injected(filter), []);
});

// family is free text in the bridge DetectionRecord (the Rust gateway ingest
// derives it from the class); it lands in aria-label and <option value>.
test('a sensor-supplied signal family cannot break out of anomaly attributes', async () => {
    const anomalies = [{ id: 1, detection_id: 'a', signal_class: 'dmr', family: QUOTE, anomaly_score: 0.9 }];
    const f = panel({ anomalies });
    await loadAnomalies(f, 'family');
    change(f, f.el('rf-anomaly-filter-key'), 'family');
    assert.deepEqual(injected(f.el('anomaly-queue')), []);
    assert.deepEqual(injected(f.el('rf-anomaly-filter-val')), []);
});

test('escalating selected anomalies does not dismiss them', async () => {
    const anomalies = [{ id: 1, detection_id: 'a', signal_class: 'dmr', anomaly_score: 0.9 },
        { id: 2, detection_id: 'b', signal_class: 'dmr', anomaly_score: 0.8 }];
    const f = panel({ anomalies });
    await loadAnomalies(f, 'signal_class');
    const all = f.el('rf-select-all');
    all.checked = true;
    all.dispatchEvent(new f.context.Event('change'));
    f.answerConfirm(true);
    const before = f.writes().length;
    f.el('rf-bulk-escalate').click();
    await settle();
    // The escalation is sent, names every selected anomaly, and dismisses none.
    const sent = f.writes().slice(before);
    assert.ok(sent.length, 'escalation was requested');
    for (const call of sent) assert.doesNotMatch(call.url, /dismiss/, call.url);
    const named = idsNamed(sent);
    for (const id of ['1', '2']) assert.ok(named.has(id), [...named].join(' '));
});

test('an escalation raises an alert through the escalation endpoint and says what it did, or why it failed', async () => {
    const anomalies = [{ id: 1, detection_id: 'a', signal_class: 'dmr', anomaly_score: 0.9 },
        { id: 2, detection_id: 'b', signal_class: 'dmr', anomaly_score: 0.8 },
        { id: 3, detection_id: 'c', signal_class: 'fm', anomaly_score: 0.7 }];
    let answer = { ok: true, alert_id: 'alert_9', escalated_count: 1, escalated: [1], already_escalated: [2], not_found: [3] };
    const f = panel({ anomalies, routes: (url, opts) => (opts.method === 'POST' && url === '/api/detections/anomalies/bulk/escalate' ? answer : undefined) });
    await loadAnomalies(f, 'signal_class');
    const selectAll = () => {
        const all = f.el('rf-select-all');
        all.checked = true;
        all.dispatchEvent(new f.context.Event('change'));
    };
    selectAll();
    f.answerConfirm(true);
    f.el('rf-bulk-escalate').click();
    await settle();
    const write = f.lastWrite();
    assert.deepEqual([write.method, write.url, write.headers['X-CSRF-Token']], ['POST', '/api/detections/anomalies/bulk/escalate', CSRF]);
    assert.deepEqual(f.body(write), { ids: ['1', '2', '3'] });
    assert.equal(f.dialogs.at(-1)[1], 'Escalate 3 selected anomalies? One critical alert names them; none is dismissed.');
    assert.equal(f.toasts().at(-1), 'Critical alert raised for 1 anomaly; 1 already escalated; 1 not found');
    assert.equal(f.el('rf-bulk-count').textContent, '0 selected', 'the selection is cleared');
    assert.equal(cards(f).length, 2, 'the escalated anomalies stay in the queue');

    answer = { ok: true, alert_id: null, escalated_count: 0, escalated: [], already_escalated: [1, 2, 3], not_found: [] };
    selectAll();
    f.el('rf-bulk-escalate').click();
    await settle();
    assert.equal(f.toasts().at(-1), 'No new alert; 3 already escalated');

    answer = response(403, { detail: 'Insufficient role: analyst required' });
    selectAll();
    f.el('rf-bulk-escalate').click();
    await settle();
    assert.equal(f.toasts().at(-1), 'Bulk escalation failed: Insufficient role: analyst required');
    assert.equal(f.el('rf-bulk-count').textContent, '3 selected', 'a refused escalation keeps the selection');
});

test('an escalation naming more anomalies than the server accepts is not sent', async () => {
    const anomalies = Array.from({ length: 101 }, (_, i) => ({ id: i + 1, detection_id: 'd' + i, signal_class: 'dmr', anomaly_score: 0.9 }));
    const f = panel({ anomalies });
    await loadAnomalies(f);
    const all = f.el('rf-select-all');
    all.checked = true;
    all.dispatchEvent(new f.context.Event('change'));
    assert.equal(f.el('rf-bulk-count').textContent, '101 selected');
    f.answerConfirm(true);
    const writes = f.writes().length, dialogs = f.dialogs.length;
    f.el('rf-bulk-escalate').click();
    await settle();
    assert.equal(f.writes().length, writes, 'nothing is sent');
    assert.equal(f.dialogs.length, dialogs, 'nothing is asked');
    assert.equal(f.toasts().at(-1), 'Escalate at most 100 anomalies at a time (101 selected)');
    assert.equal(f.el('rf-bulk-count').textContent, '101 selected', 'the selection is kept');

    // 100 is the limit, not over it.
    const box = f.el('anomaly-queue').querySelector('[data-rf-bulk-id="101"]');
    assert.ok(box, 'anomaly 101 has a selection box');
    box.checked = false;
    box.dispatchEvent(new f.context.Event('change'));
    f.el('rf-bulk-escalate').click();
    await settle();
    assert.equal(f.lastWrite().url, '/api/detections/anomalies/bulk/escalate');
    assert.equal(f.body(f.lastWrite()).ids.length, 100);
});

test('IQ download and export links never put the API key in a URL', async () => {
    const key = 'key-' + 'K'.repeat(40);
    const anomalies = [{ id: 1, detection_id: 'd-1', signal_class: 'dmr', anomaly_score: 0.9, has_iq_capture: true }];
    const f = panel({ cookie: '', apiKey: key, anomalies, routes: url => url.startsWith('/api/detections/d-1/iq?')
        ? { constellation_x: [0, 1], constellation_y: [1, 0] } : undefined });
    await loadAnomalies(f, 'signal_class');
    cards(f)[0].querySelector('[data-investigate-group]').click();
    await settle();
    f.el('dd-download-iq').click();
    f.el('dd-export').click();
    const all = f.el('rf-select-all');
    all.checked = true;
    all.dispatchEvent(new f.context.Event('change'));
    f.el('rf-bulk-export').click();
    const opened = f.navigations.filter(url => url.startsWith('open:'));
    assert.equal(opened.length, 3);
    for (const url of opened) assert.ok(!url.includes(key), url);
});

test('IQ download and export links are the exact key-free paths for the exact detection', async () => {
    const anomalies = [{ id: 4, detection_id: 'd 4/x', signal_class: 'p25', anomaly_score: 0.9, has_iq_capture: true }];
    const f = panel({ cookie: '', apiKey: 'key-' + 'J'.repeat(40), anomalies, routes: url => url.startsWith('/api/detections/d%204%2Fx/iq?')
        ? { constellation_x: [0, 1], constellation_y: [1, 0] } : undefined });
    await loadAnomalies(f, 'signal_class');
    cards(f)[0].querySelector('[data-investigate-group]').click();
    await settle();
    f.el('dd-download-iq').click();
    f.el('dd-export').click();
    const all = f.el('rf-select-all');
    all.checked = true;
    all.dispatchEvent(new f.context.Event('change'));
    f.el('rf-bulk-export').click();
    assert.deepEqual(f.navigations.filter(url => url.startsWith('open:')), [
        'open:/api/detections/d%204%2Fx/iq?format=raw',
        'open:/api/export/detections?class=p25&hours=' + f.dd.timeRange,
        'open:/api/export/rf_anomalies?format=json&ids=4']);
});

test('deep-dive feedback, baseline and corroboration use exact IDs and show class/node names as text', async () => {
    const detection = { id: 5, detection_id: 'det 5/a', signal_class: 'dmr', node_id: 'edge-1', anomaly_score: 0.8, snr_db: -3,
        confidence: 0.3, baseline_status: 'drift', timestamp: new Date().toISOString(), has_iq_capture: true };
    const f = panel({ anomalies: [detection], routes: url => {
        if (url.startsWith('/api/detections/distribution')) return [{ signal_class: MARKUP }, { signal_class: 'dmr' }];
        if (url.startsWith('/api/detections/recent?minutes=60&limit=200')) return { detections: [{ signal_class: 'dmr', node_id: '<b>edge-9</b>' }] };
        if (url.startsWith('/api/detections/det%205%2Fa/iq?format=json')) return { constellation_x: [0, 1], constellation_y: [1, 0] };
        return undefined;
    } });
    f.el('dd-feedback-group').innerHTML = '<button data-feedback="false_positive">FP</button>';
    await loadAnomalies(f, 'signal_class');
    cards(f)[0].querySelector('[data-investigate-group]').click();
    await settle();
    // The captured IQ of exactly this detection is fetched and offered for download.
    assert.deepEqual(f.requests.filter(call => /\/iq\?/.test(call.url)).map(call => call.url.replace(/&_t=\d+$/, '')),
        ['/api/detections/det%205%2Fa/iq?format=json']);
    assert.equal(f.el('dd-download-iq').style.display, '');
    f.el('dd-download-iq').click();
    assert.deepEqual(f.navigations, ['open:/api/detections/det%205%2Fa/iq?format=raw']);
    const baseline = f.el('dd-baseline');
    assert.ok(baseline.textContent.includes('Match — dmr is expected'));
    assert.ok(baseline.querySelectorAll('.baseline-class-tag').some(tag => tag.textContent === MARKUP));
    assert.deepEqual(injected(baseline), []);
    const checklist = f.el('dd-investigation-checklist');
    assert.ok(checklist.textContent.includes('(<b>edge-9</b>)'), checklist.textContent);
    assert.equal(f.el('dd-investigation-recommendation').querySelector('.inv-rec-action').textContent, 'Escalate');
    assert.deepEqual(injected(checklist), []);
    f.el('dd-feedback-group').querySelector('[data-feedback]').click();
    await settle();
    assert.equal(f.lastWrite().url, '/api/detections/anomalies/det%205%2Fa/feedback');
    assert.deepEqual(f.body(f.lastWrite()), { label: 'false_positive' });
    f.el('dd-mark-known').click();
    assert.deepEqual(f.known, ['det 5/a']);
});

test('Capture IQ from a deep dive targets the detection node and frequency and tags only a well-formed class', async () => {
    const now = new Date().toISOString();
    const anomalies = [
        { id: 1, detection_id: 'a', signal_class: 'lora/css', node_id: 'edge-1', freq_hz: 868.1e6, anomaly_score: 0.9, timestamp: now },
        { id: 2, detection_id: 'b', signal_class: 'fm wide', node_id: 'edge-1', freq_hz: 100.1e6, anomaly_score: 0.5, timestamp: now }];
    const f = panel({ anomalies, routes: (url, options) => url.startsWith('/api/nodes/?')
        ? [{ node_id: 'edge-0', host: 'h0', status: 'active' }, { node_id: 'edge-1', host: 'h1', status: 'active' }]
        : options.method === 'POST' ? {} : undefined });
    await loadAnomalies(f, 'signal_class');
    const captureFrom = async index => {
        cards(f)[index].querySelector('[data-investigate-group]').click();
        await settle();
        f.el('dd-capture-iq').click();
        await settle();
        assert.equal(f.el('iq-capture-node-id').value, 'edge-1');
        f.el('iq-capture-submit').click();
        await settle();
        const call = f.lastWrite();
        assert.equal(call.url, '/api/nodes/edge-1/capture');
        assert.equal(call.headers['X-CSRF-Token'], CSRF);
        return f.body(call);
    };
    assert.deepEqual(cards(f).map(card => card.querySelector('strong').textContent), ['lora/css', 'fm wide']);
    assert.deepEqual(await captureFrom(0), { freq_hz: 868100000, duration_ms: 1000, sample_rate: 2400000, signal_class: 'lora/css' });
    // A class outside the server's pattern is not forwarded; the capture still goes ahead.
    assert.deepEqual(await captureFrom(1), { freq_hz: 100100000, duration_ms: 1000, sample_rate: 2400000 });
});

test('the IQ capture inventory and queue render node, class, tier and status strings as text', async () => {
    const rows = [{ detection_id: 'd-1', node_id: MARKUP, signal_class: '<b>c</b>', tier: '<i>t</i>', freq_hz: 1e6,
        n_samples: 2048, file_size_bytes: 4096, quality_score: 0.5, captured_at: new Date().toISOString() }];
    const commands = [{ command: 'iq_capture', node_id: MARKUP, status: '<b>queued</b>', params: { freq_hz: 1e6, duration_ms: 1000 } },
        { command: 'ping', node_id: 'other' }];
    const f = panel({ routes: url => {
        if (url.startsWith('/api/iq/index')) return rows;
        if (url.startsWith('/api/nodes/commands')) return commands;
        if (url.startsWith('/api/iq/stats')) return { total_captures: 1 };
        return undefined;
    } });
    await f.tick(FIRST_LOADS_MS);
    const tbody = f.el('iq-captures-tbody');
    assert.equal(tbody.querySelectorAll('td')[1].textContent, MARKUP);
    assert.equal(tbody.querySelector('.signal-class-badge').textContent, '<b>c</b>');
    assert.ok(tbody.textContent.includes('<i>t</i>'));
    assert.deepEqual(f.el('iq-filter-node').options.map(option => [option.value, option.textContent]), [['', 'All Nodes'], [MARKUP, MARKUP]]);
    assert.deepEqual(injected(f.el('iq-filter-node')), []);
    const queue = f.el('iq-commands-list');
    assert.equal(queue.querySelectorAll('tr').length, 2, 'only IQ capture commands are listed');
    assert.ok(queue.textContent.includes(MARKUP) && queue.textContent.includes('<b>queued</b>'));
    for (const el of [tbody, queue]) assert.deepEqual(injected(el), []);
    tbody.querySelector('[data-iq-view]').click();
    await settle();
    assert.ok(f.requests.some(call => call.url.startsWith('/api/detections/d-1/iq?')));
});

test('feed and anomaly failures show a retry state instead of stale or partial markup', async () => {
    let fail = true;
    const f = panel({ routes: url => (fail && (url.startsWith('/api/detections/recent') || url.startsWith('/api/detections/anomalies?'))
        ? response(503, {}) : undefined) });
    await f.tick(FIRST_LOADS_MS);
    assert.ok(f.el('det-feed-tbody').textContent.includes('Failed to load detection feed'));
    assert.ok(f.el('anomaly-queue').textContent.includes('Failed to load anomalies'));
    fail = false;
    f.el('det-feed-tbody').querySelector('.retry-btn').click();
    f.el('anomaly-queue').querySelector('.retry-btn').click();
    await settle();
    assert.equal(f.el('det-feed-tbody').textContent, '');
    assert.equal(f.el('anomaly-queue').textContent, '');
});
