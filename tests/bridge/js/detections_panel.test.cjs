/* The shipped RF Intelligence panels (detections.js) built from index.html:
 * charts, the detection feed, the grouped anomaly queue, re-evaluation, the
 * deep dive, its investigation checklist and the IQ capture inventory.
 * Server data is often empty, partial or from an older API shape; the panel
 * must still show the operator what is (and is not) known. */
const assert = require('node:assert/strict');
const test = require('node:test');
const { bootDashboard, response, settle } = require('./untrusted_dom.cjs');

const PANELS = ['panel-detections', 'panel-anomalies', 'panel-iq-captures', 'deep-dive-overlay'];
const plain = value => JSON.parse(JSON.stringify(value));
const NOT_JSON = () => response(503, '<html>unavailable</html>', 'text/html');
const clock = (hour, minute) => new Date(2026, 10, 10, hour, minute).toISOString();
const hhmm = iso => new Date(iso).toLocaleTimeString(undefined, { hour12: false, hour: '2-digit', minute: '2-digit' });

function panel({ routes = () => undefined, activate = true, ...options } = {}) {
    const f = bootDashboard({ ids: PANELS, subtrees: PANELS, scripts: ['chart_utils.js', 'detections.js'], ...options,
        routes: (url, opts, call) => {
            const answer = routes(url, opts, call);
            if (answer !== undefined) return answer;
            return opts.method && opts.method !== 'GET' ? {} : undefined;
        } });
    f.dd = f.db.detectionDashboard;
    f.known = [];
    f.context.KnownSignals = { open: (db, id) => f.known.push(id), bind() {} };
    f.drills = [];
    f.context.drillDown.toSpectrum = hz => f.drills.push(['spectrum', hz]);
    f.context.drillDown.toSignalClass = cls => f.drills.push(['class', cls]);
    if (activate) f.dd.activate();
    return f;
}
const change = (f, el, value) => { el.value = value; el.dispatchEvent(new f.context.Event('change')); };
const cards = f => f.el('anomaly-queue').querySelectorAll('.anomaly-card');
const labels = f => cards(f).map(card => [card.querySelector('strong').textContent, card.querySelector('.anomaly-group-badge').textContent]);
const urls = (f, prefix) => f.requests.map(call => call.url.replace(/[?&]_t=\d+$/, '')).filter(url => url.startsWith(prefix));
const timeRange = (f, label) => f.el('panel-detections').querySelectorAll('.det-timeline-btn[data-range]').find(b => b.textContent === label);

/* What the operator sees drawn on a canvas: every fillText string. */
function canvasText(el) {
    const texts = [];
    const ctx = new Proxy({ createImageData: (w, h) => ({ data: new Uint8ClampedArray(w * h * 4) }) }, {
        get: (target, key) => (key in target ? target[key]
            : key === 'fillText' ? text => texts.push(String(text)) : () => ({ addColorStop() {}, width: 0 })),
        set: (target, key, value) => { target[key] = value; return true; },
    });
    el.getContext = () => ctx;
    return texts;
}
/* The same canvas labels, in any drawing order. */
const sameText = (drawn, expected, message) => assert.deepEqual([...drawn].sort(), [...expected].sort(), message);
/* The data each chart was asked to draw (the real ChartUtils still draws it). */
function chartCalls(f) {
    const calls = {};
    const charts = f.context.ChartUtils;
    for (const name of ['drawStackedArea', 'drawTreemap', 'drawHeatmap', 'drawSparkline', 'clearCanvas']) {
        const original = charts[name];
        calls[name] = [];
        charts[name] = (...args) => { calls[name].push(args); return original.apply(charts, args); };
    }
    return calls;
}

test('detection charts show loading, empty and failed states, and plot exactly the rows the API returned', async () => {
    let mode = 'empty';
    const rows = {
        timeline: [{ bucket: clock(10, 0), count: 3 }, { bucket: clock(10, 5) }],
        distribution: [{ signal_class: 'qpsk', family: 'psk', count: 5 }, { signal_class: 'mystery', family: 'zzz' }],
        heatmap: [{ time_bucket: 0, freq_bucket_mhz: 433, count: 4 }, { time_bucket: 1, freq_bucket_mhz: 435, count: 2 }],
    };
    const f = panel({ activate: false, routes: url => {
        const chart = /^\/api\/detections\/(timeline|distribution|heatmap)\?hours=\d+(&|$)/.exec(url);
        if (!chart) return undefined;
        if (mode === 'fail') return NOT_JSON();
        return mode === 'empty' ? [] : rows[chart[1]];
    } });
    const calls = chartCalls(f);
    const drawn = Object.fromEntries(['timeline', 'treemap', 'heatmap'].map(name => [name, canvasText(f.el(`det-${name}-canvas`))]));
    f.dd.activate();
    await f.tick(1000);
    assert.deepEqual(drawn.timeline, ['Loading timeline...', 'No timeline data']);
    assert.deepEqual(drawn.treemap, ['Loading class distribution...', 'No class data']);
    assert.deepEqual(drawn.heatmap, ['Loading frequency heatmap...', 'No heatmap data']);

    mode = 'fail';
    for (const name in drawn) drawn[name].length = 0;
    timeRange(f, '6h').click();
    await settle();
    assert.equal(drawn.timeline.at(-1), 'Failed to load timeline');
    assert.equal(drawn.treemap.at(-1), 'No class data', 'a failed distribution shows no classes, never stale tiles');
    assert.equal(drawn.heatmap.at(-1), 'Failed to load heatmap');
    assert.ok(timeRange(f, '6h').classList.contains('active') && !timeRange(f, '1h').classList.contains('active'));

    mode = 'data';
    timeRange(f, '24h').click();
    await settle();
    const [, , series, colors, timeLabels] = calls.drawStackedArea.at(-1);
    assert.deepEqual(plain(series), [[3, 0]], 'a bucket without a count is drawn as zero');
    assert.deepEqual(plain(colors), ['#3fb950']);
    assert.deepEqual(plain(timeLabels), [hhmm(rows.timeline[0].bucket), hhmm(rows.timeline[1].bucket)]);
    const [, , tiles, tileColor] = calls.drawTreemap.at(-1);
    assert.deepEqual(plain(tiles), [{ label: 'qpsk', value: 5, super_family: 'CONSTANT_ENVELOPE' },
        { label: 'mystery', value: 0, super_family: '' }]);
    assert.deepEqual([tileColor(tiles[0], 0), tileColor(tiles[1], 1)], ['#58a6ff', '#3fb950']);
    // Frequency rows between active buckets are filled so bands stay thin lines.
    const [, , matrix, xLabels, yLabels] = calls.drawHeatmap.at(-1);
    assert.deepEqual(plain(matrix), [[4, 0], [0, 0], [0, 2]]);
    assert.deepEqual(plain(yLabels), ['433.00 MHz', '434.00 MHz', '435.00 MHz']);
    assert.equal(xLabels.length, 2);
    const legend = () => f.el('heatmap-legend').childNodes.map(node => node.localName + ':' + node.textContent);
    assert.deepEqual(legend(), ['span:Low', 'canvas:', 'span:High']);
    timeRange(f, '7d').click();
    await settle();
    assert.deepEqual(legend(), ['span:Low', 'canvas:', 'span:High'], 'the legend is built once');
    // Each range asks for its own window, with finer heatmap buckets for shorter ones.
    assert.deepEqual(urls(f, '/api/detections/heatmap?'), ['/api/detections/heatmap?hours=1&resolution=5',
        '/api/detections/heatmap?hours=6&resolution=10', '/api/detections/heatmap?hours=24&resolution=15',
        '/api/detections/heatmap?hours=168&resolution=60']);
    assert.ok(urls(f, '/api/detections/recent?').includes('/api/detections/recent?minutes=10080&limit=50'));
});

test('class treemap tiles take the colour of their modulation super-family', async () => {
    const families = ['qam', 'PAM', 'psk', 'fsk', 'msk', 'gmsk', 'am', 'ssb', 'dsb', 'fm', 'wbfm', 'nbfm', 'ofdm', 'cdma', 'dsss', 'fhss', 'chirp', undefined];
    const f = panel({ activate: false, routes: url => (url.startsWith('/api/detections/distribution?hours=1')
        ? families.map((family, i) => ({ signal_class: 'c' + i, family, count: i + 1 })) : undefined) });
    const calls = chartCalls(f);
    f.dd.activate();
    await f.tick(1000);
    const [, , tiles, tileColor] = calls.drawTreemap.at(-1);
    assert.deepEqual(plain(tiles).map(tile => tile.super_family), ['LINEAR_DIGITAL', 'LINEAR_DIGITAL', 'CONSTANT_ENVELOPE',
        'CONSTANT_ENVELOPE', 'CONSTANT_ENVELOPE', 'CONSTANT_ENVELOPE', 'AMPLITUDE_ONLY', 'AMPLITUDE_ONLY', 'AMPLITUDE_ONLY',
        'ANALOG', 'ANALOG', 'ANALOG', 'MULTI_CARRIER', 'SPREAD_SPECTRUM', 'SPREAD_SPECTRUM', 'SPREAD_SPECTRUM', '', '']);
    assert.deepEqual([0, 6, 9, 12, 13, 16, 17].map(i => tileColor(tiles[i], i)),
        ['#3fb950', '#d29922', '#f85149', '#a371f7', '#79c0ff', '#7ee787', '#d2a8ff']);
});

test('the detection feed accepts the legacy array shape and shows unknown fields as placeholders', async () => {
    const feed = [
        { signal_class: 'fm', freq_hz: 100e6, node_id: 'edge-1', is_anomaly: true, anomaly_score: 0.2, snr_db: 5, confidence: 0.5 },
        { freq_band: '2.40 GHz' },
        { signal_class: 'tone' }];
    const f = panel({ routes: url => (url.startsWith('/api/detections/recent?minutes=60&limit=50') ? feed : undefined) });
    await settle();
    const rows = f.el('det-feed-tbody').querySelectorAll('.det-feed-row');
    const cells = row => row.querySelectorAll('td').map(td => td.textContent);
    assert.equal(f.el('det-count-badge').textContent, '3');
    assert.equal(f.el('det-feed-empty').style.display, 'none');
    assert.deepEqual(rows.map(cells), [
        ['fm', '100.00 MHz', 'edge-1', '1', '50%', '5.0 dB', '--', '0.20'],
        ['unknown', '2.40 GHz', '--', '1', '0%', '--', '--', '--'],
        ['tone', '--', '--', '1', '0%', '--', '--', '--']]);
    assert.deepEqual(rows.map(row => row.classList.contains('anomaly-row')), [true, false, false]);
    // Drill-downs hand the exact class and the parsed frequency to the other tabs.
    rows[0].querySelector('[data-drilldown-class]').click();
    rows[0].querySelector('[data-drilldown-freq]').click();
    rows[1].querySelector('[data-drilldown-freq]').click();
    rows[2].querySelector('[data-drilldown-freq]').click();
    assert.deepEqual(f.drills, [['class', 'fm'], ['spectrum', 100e6], ['spectrum', 2.4e9]], 'an unknown frequency opens nothing');
    assert.equal(f.el('deep-dive-overlay').style.display, 'none', 'a drill-down does not also open the deep dive');
});

test('auto-refresh, repeated activation and deactivation control which polls run', async () => {
    const f = panel();
    const feedPolls = () => urls(f, '/api/detections/recent?minutes=60&limit=50').length;
    const commandPolls = () => urls(f, '/api/nodes/commands').length;
    f.dd.activate();
    assert.equal(feedPolls(), 1, 'activating an active panel starts nothing twice');
    await f.tick(8000);
    assert.equal(feedPolls(), 2);
    const auto = f.el('det-auto-refresh');
    assert.equal(auto.checked, true, 'index.html starts with auto-refresh on');
    auto.checked = false;
    auto.dispatchEvent(new f.context.Event('change'));
    await f.tick(16000);
    assert.equal(feedPolls(), 2, 'auto-refresh off stops the feed poll');
    assert.equal(commandPolls(), 1, 'the IQ queue poll also pauses');
    auto.checked = true;
    auto.dispatchEvent(new f.context.Event('change'));
    await f.tick(10000);
    assert.equal(feedPolls(), 3);
    const commands = commandPolls();
    assert.equal(commands, 2, 'the IQ queue is polled every 10 s');
    f.dd.deactivate();
    await f.tick(30000);
    assert.equal(feedPolls(), 3);
    assert.equal(commandPolls(), commands, 'deactivation also stops the IQ queue poll');
});

test('the anomaly KPI prefers the server count and never shows an undefined value', async () => {
    let answer = { count: 7, anomalies: [] };
    const f = panel({ routes: url => (url.startsWith('/api/detections/anomalies?min_score=0.3&limit=1000') ? answer : undefined) });
    await settle();
    assert.equal(f.el('det-kpi-anomalies').textContent, '7');
    answer = { anomalies: [{}, {}] };
    await f.tick(15000);
    assert.equal(f.el('det-kpi-anomalies').textContent, '2');
    answer = {};
    await f.tick(15000);
    assert.equal(f.el('det-kpi-anomalies').textContent, '0');
});

const T1 = clock(9, 5), T2 = clock(9, 35);
const GROUPED = [
    { id: 1, detection_id: 'a', signal_class: 'dmr', family: 'fsk', node_id: 'edge-1', anomaly_score: 0.9, freq_hz: 446e6,
        dimensions: { spectral: 0.2, temporal: 0.7 }, timestamp: T2, seen_count: 3 },
    { id: 2, detection_id: 'b', signal_class: 'dmr', anomaly_score: 0.55, freq_hz: 446.1e6, dimensions: {}, detected_at: T1 },
    { id: 3, detection_id: 'c', node_id: 'edge-2', priority: 'critical', anomaly_score: null, dimensions: 'bogus', timestamp: T2, has_iq_capture: true }];

test('every grouping the page offers groups anomalies by the stored value, with "Unknown" for a missing one', async () => {
    const f = panel({ routes: url => (url.startsWith('/api/detections/anomalies?limit=50') ? { anomalies: GROUPED, total: 3 } : undefined) });
    await f.tick(2000);
    const expected = {
        signal_class: [['dmr', '2'], ['Unknown', '1']],
        family: [['fsk', '1'], ['Unknown', '2']],
        node_id: [['edge-1', '1'], ['Unknown', '1'], ['edge-2', '1']],
        priority: [['critical', '2'], ['anomalous', '1']],
        band: [['70cm Amateur', '2'], ['Unknown', '1']],
        dimension: [['temporal', '1'], ['Unknown', '2']],
    };
    for (const [key, groups] of Object.entries(expected)) {
        change(f, f.el('rf-anomaly-group-select'), key);
        assert.equal(f.el('rf-anomaly-group-select').value, key, 'the page offers ' + key);
        assert.deepEqual(labels(f), groups, key);
    }
    change(f, f.el('rf-anomaly-group-select'), 'signal_class');
    const [dmr, unknown] = cards(f);
    assert.equal(dmr.querySelector('.seen-count').textContent, 'seen 4x');
    assert.ok(dmr.textContent.includes(hhmm(T1) + ' — ' + hhmm(T2)), 'the group spans its earliest to latest anomaly');
    assert.ok(dmr.textContent.includes('Nodes: edge-1'));
    assert.equal(dmr.querySelector('.rf-band-label').textContent, '70cm Amateur');
    assert.equal(dmr.querySelector('.rf-class-desc').textContent, 'Freq Shift Keying');
    assert.ok(!dmr.querySelector('.iq-badge') && unknown.querySelector('.iq-badge'));
    assert.ok(unknown.classList.contains('priority-normal'), 'a missing score is treated as zero');
    assert.equal(unknown.querySelector('.anomaly-score-badge').textContent, '0.00');
    assert.ok(unknown.textContent.includes('Nodes: edge-2') && unknown.textContent.includes('--'));
    dmr.querySelector('[data-drilldown-anomaly-freq]').click();
    dmr.querySelector('[data-drilldown-anomaly-class]').click();
    unknown.querySelector('[data-drilldown-anomaly-freq]').click();
    assert.deepEqual(f.drills, [['spectrum', 446e6], ['class', 'dmr']], 'a group without a frequency drills nowhere');

    // Clearing the filter key hides the value list and shows every anomaly again.
    change(f, f.el('rf-anomaly-filter-key'), 'node_id');
    change(f, f.el('rf-anomaly-filter-val'), 'edge-2');
    assert.equal(f.el('anomaly-count-badge').textContent, '1 / 3');
    change(f, f.el('rf-anomaly-filter-key'), '');
    assert.equal(f.el('rf-anomaly-filter-val').style.display, 'none');
    assert.equal(f.el('anomaly-count-badge').textContent, '3');
    assert.deepEqual(labels(f), expected.signal_class);
});

test('a group label names the radio band of its frequency', async () => {
    const bands = [[0.01, 'VLF'], [0.1, 'LF'], [1, 'MF'], [27.185, 'CB 27 MHz'], [14, 'HF'], [50, 'VHF Low'], [100, 'FM Broadcast'],
        [121.5, 'Aviation VHF'], [146, '2m Amateur'], [160, 'VHF Business'], [140, 'VHF High'], [200, 'VHF'], [315.05, 'ISM 315 MHz'],
        [300, 'Military UHF'], [405, 'UHF SATCOM'], [433.92, 'ISM 433 MHz'], [445, '70cm Amateur'], [460, 'UHF Business'],
        [600, 'UHF TV'], [868, 'ISM 868 MHz'], [915, 'ISM 915 MHz'], [800, 'Cellular 700-900'], [1090.05, 'ADS-B 1090'],
        [1000, 'L-Band Aero'], [1250, '23cm Amateur'], [1540, 'L-Band SATCOM'], [1575.42, 'GPS/GNSS L1'], [1900, 'Cellular AWS/PCS'],
        [2437, 'ISM 2.4 GHz'], [2600, 'BRS/EBS 2.5 GHz'], [2300, 'UHF'], [3500, '5G C-Band'], [5500, 'ISM 5 GHz'],
        [6500, 'WiFi 6E / 6 GHz'], [10000, 'SHF'], [40000, 'EHF']];
    const anomalies = bands.map(([mhz], i) => ({ id: i + 1, detection_id: 'd' + i, signal_class: 'c' + i, anomaly_score: 0.5, freq_hz: mhz * 1e6 }));
    const f = panel({ routes: url => (url.startsWith('/api/detections/anomalies?limit=50') ? { anomalies, total: 99 } : undefined) });
    await f.tick(2000);
    change(f, f.el('rf-anomaly-group-select'), 'signal_class');
    assert.equal(f.el('anomaly-count-badge').textContent, bands.length + ' / 99', 'the badge says the page is not the whole queue');
    const shown = Object.fromEntries(cards(f).map(card => [card.querySelector('strong').textContent, card.querySelector('.rf-band-label').textContent]));
    assert.deepEqual(bands.map(([mhz], i) => [mhz, shown['c' + i]]), bands);
});

test('live frames are capped: the feed keeps 200 detections and the queue 50 anomalies', async () => {
    const f = panel();
    await f.tick(2000);
    change(f, f.el('rf-anomaly-group-select'), 'node_id');
    const socket = f.sockets.find(s => s.url === 'wss://bridge.test/api/detections/ws/feed');
    socket.open();
    for (let i = 0; i < 201; i++) socket.message({ type: 'detection', detection: { signal_class: 'c' + i, node_id: 'edge-1' } });
    for (let i = 0; i < 51; i++) socket.message({ type: 'anomaly', anomaly: { id: i, signal_class: 'p25', node_id: 'n' + i, anomaly_score: 0.6 } });
    await f.tick(1000);
    assert.equal(f.el('det-count-badge').textContent, '200');
    assert.equal(f.el('anomaly-count-badge').textContent, '50');
    assert.equal(cards(f).length, 50);
    assert.ok(!cards(f).some(card => card.querySelector('strong').textContent === 'n0'), 'the oldest anomaly is the one dropped');
});

test('keyboard shortcuts move through anomaly cards and act on the focused one only', async () => {
    // The legacy API shape: a bare array of anomalies.
    const f = panel({ activate: false, routes: url => (url.startsWith('/api/detections/anomalies?limit=50') ? GROUPED : undefined) });
    const key = (k, target = f.document.body) => f.fire('keydown', { key: k, target });
    const focused = () => cards(f).map(card => card.classList.contains('focused'));
    // Pressed before the queue has loaded any card (k last: it would clamp focus to the first card).
    key('j', f.document);
    key('k', f.document);
    f.dd.activate();
    await f.tick(2000);
    change(f, f.el('rf-anomaly-group-select'), 'node_id');
    assert.deepEqual(focused(), [false, false, false], 'a key pressed before any card was shown moves nothing');
    for (const k of ['d', 'i', 'b', '?']) key(k);
    await settle();
    assert.equal(f.writes().length, 0, 'nothing is focused yet');
    assert.deepEqual([f.known, f.el('deep-dive-overlay').style.display], [[], 'none']);
    key('j'); key('ArrowDown'); key('j'); key('j');
    assert.deepEqual(focused(), [false, false, true], 'focus stops at the last card');
    key('k');
    assert.deepEqual(focused(), [false, true, false]);
    key('j', f.el('rf-anomaly-filter-key'));
    key('j', f.document.createElement('input'));
    key('j', f.document.createElement('textarea'));
    assert.deepEqual(focused(), [false, true, false], 'typing in a control does not move focus');
    key('b');
    assert.deepEqual(f.known, ['b'], 'b reviews the focused group');
    key('d');
    await settle();
    assert.deepEqual(f.body(f.lastWrite()), { ids: [2] });
    key('ArrowUp');
    key('i');
    await settle();
    assert.equal(f.el('deep-dive-overlay').style.display, '');
    assert.equal(f.el('deep-dive-title').textContent, 'Deep-Dive: dmr');
    const writes = f.writes().length;
    key('d');
    await settle();
    assert.equal(f.writes().length, writes, 'shortcuts are ignored while the deep dive is open');
});

test('grouped selection: unticking a group deselects exactly its members, and a group without IDs dismisses nothing', async () => {
    const anomalies = [{ id: 1, signal_class: 'dmr', node_id: 'a', anomaly_score: 0.9 }, { id: 2, signal_class: 'dmr', node_id: 'b', anomaly_score: 0.8 },
        { detection_id: 'x', signal_class: 'fm', anomaly_score: 0.4 }, { id: 4, signal_class: 'p25', anomaly_score: 0.35 }];
    const f = panel({ routes: url => (url.startsWith('/api/detections/anomalies?limit=50') ? { anomalies } : undefined) });
    await f.tick(2000);
    change(f, f.el('rf-anomaly-group-select'), 'signal_class');
    assert.equal(f.el('rf-bulk-bar').style.display, '');
    const box = cards(f)[0].querySelector('[data-rf-bulk-group]');
    box.checked = true;
    box.dispatchEvent(new f.context.Event('change'));
    assert.equal(f.el('rf-bulk-count').textContent, '2 selected');
    assert.equal(f.el('rf-bulk-dismiss').disabled, false);
    box.checked = false;
    box.dispatchEvent(new f.context.Event('change'));
    assert.equal(f.el('rf-bulk-count').textContent, '0 selected');
    assert.ok(!cards(f)[0].classList.contains('bulk-selected'));
    assert.equal(f.el('rf-bulk-dismiss').disabled, true);
    cards(f)[1].querySelector('[data-dismiss-group]').click();
    await settle();
    assert.equal(f.writes().length, 0, 'an anomaly without a stored ID cannot be dismissed by guesswork');
    // Only a group of several anomalies asks first (detections_rendering covers that prompt).
    f.answerConfirm(false);
    cards(f)[2].querySelector('[data-dismiss-group]').click();
    await settle();
    assert.equal(f.dialogs.length, 0, 'a group of one is dismissed without a prompt');
    assert.deepEqual([f.lastWrite().url, f.body(f.lastWrite())], ['/api/detections/anomalies/bulk/dismiss', { ids: [4] }]);
});

test('Select all dismisses only anomalies by their stored row ID', async () => {
    const anomalies = [{ id: 5, signal_class: 'dmr', anomaly_score: 0.9 }, { detection_id: 'det-x', signal_class: 'fm', anomaly_score: 0.6 },
        { signal_class: 'p25', anomaly_score: 0.5 }];
    const f = panel({ routes: url => (url.startsWith('/api/detections/anomalies?limit=50') ? { anomalies } : undefined) });
    await f.tick(2000);
    change(f, f.el('rf-anomaly-group-select'), 'signal_class');
    const all = f.el('rf-select-all');
    all.checked = true;
    all.dispatchEvent(new f.context.Event('change'));
    f.answerConfirm(true);
    f.el('rf-bulk-dismiss').click();
    await settle();
    assert.deepEqual(f.body(f.lastWrite()).ids.map(String), ['5']);
});

test('the bulk-action bar hides once the last RF anomaly is gone', async () => {
    const anomalies = [{ id: 1, signal_class: 'dmr', anomaly_score: 0.9 }, { id: 2, signal_class: 'fm', anomaly_score: 0.6 }];
    const f = panel({ routes: url => (url.startsWith('/api/detections/anomalies?limit=50') ? { anomalies } : undefined) });
    await f.tick(2000);
    change(f, f.el('rf-anomaly-group-select'), 'signal_class');
    const all = f.el('rf-select-all');
    all.checked = true;
    all.dispatchEvent(new f.context.Event('change'));
    anomalies.length = 0;
    f.answerConfirm(true);
    f.el('rf-bulk-dismiss').click();
    await settle();
    assert.equal(f.el('anomaly-empty').style.display, '');
    assert.equal(f.el('rf-bulk-bar').style.display, 'none');
});

test('in the flat queue only anomalies with a row ID can be selected, and select-all is ticked once they all are', async () => {
    const anomalies = [{ id: 5, signal_class: 'dmr', anomaly_score: 0.9 }, { detection_id: 'det-x', signal_class: 'fm', anomaly_score: 0.6 },
        { signal_class: 'p25', anomaly_score: 0.5 }];
    const f = panel({ routes: url => (url.startsWith('/api/detections/anomalies?limit=50') ? { anomalies } : undefined) });
    await f.tick(2000);
    const boxes = f.el('anomaly-queue').querySelectorAll('.bulk-checkbox');
    assert.equal(boxes.length, 3);
    assert.deepEqual(boxes.map(box => [box.getAttribute('data-rf-bulk-id'), box.hasAttribute('disabled')]), [['5', false], [null, true], [null, true]]);
    const box = f.el('anomaly-queue').querySelector('[data-rf-bulk-id="5"]');
    box.checked = true;
    box.dispatchEvent(new f.context.Event('change'));
    assert.equal(f.el('rf-select-all').checked, true, 'every selectable anomaly is selected');
    f.el('rf-bulk-dismiss').click();
    await settle();
    assert.deepEqual(f.body(f.lastWrite()), { ids: ['5'] });
});

test('a group without row IDs selects nothing, and a poll that empties the queue drops the selection and hides the bulk bar', async () => {
    let anomalies = [{ id: 1, signal_class: 'dmr', anomaly_score: 0.9 }, { detection_id: 'det-x', signal_class: 'fm', anomaly_score: 0.6 }];
    const f = panel({ routes: url => (url.startsWith('/api/detections/anomalies?limit=50') ? { anomalies } : undefined) });
    await f.tick(2000);
    change(f, f.el('rf-anomaly-group-select'), 'signal_class');
    const boxes = cards(f).map(card => card.querySelector('.bulk-checkbox'));
    assert.deepEqual(boxes.map(box => [box.getAttribute('data-rf-bulk-group'), box.hasAttribute('disabled')]), [['1', false], [null, true]],
        'a group with no stored row ID gets a disabled box, as a single card without one does');
    const empty = boxes[1];
    empty.checked = true;
    empty.dispatchEvent(new f.context.Event('change'));
    assert.equal(f.el('rf-bulk-count').textContent, '0 selected');
    const box = cards(f)[0].querySelector('[data-rf-bulk-group]');
    box.checked = true;
    box.dispatchEvent(new f.context.Event('change'));
    assert.equal(f.el('rf-bulk-count').textContent, '1 selected');
    anomalies = [];
    await f.tick(15000);
    assert.equal(f.el('anomaly-empty').style.display, '');
    assert.equal(f.el('rf-bulk-bar').style.display, 'none');
    anomalies = [{ id: 2, signal_class: 'fm', anomaly_score: 0.6 }];
    await f.tick(15000);
    assert.equal(f.el('rf-bulk-count').textContent, '0 selected', 'a vanished anomaly is no longer selected');
});

test('a critical RF anomaly reaches the threat timeline once across polls, and again when it leaves and returns', async () => {
    let anomalies = [{ id: 1, signal_class: 'dmr', freq_band: 'uhf', anomaly_score: 0.95 },
        { detection_id: 'det-x', signal_class: 'fm', freq_band: 'vhf', anomaly_score: 0.9 }];
    const f = panel({ routes: url => (url.startsWith('/api/detections/anomalies?limit=50') ? { anomalies: plain(anomalies) } : undefined) });
    const sdrEvents = () => plain(f.db._tlEvents).filter(event => event.protocol === 'sdr').map(event => event.label);
    await f.tick(2000);
    assert.deepEqual(sdrEvents(), ['dmr @ uhf', 'fm @ vhf']);
    await f.tick(30000);
    assert.deepEqual(sdrEvents(), ['dmr @ uhf', 'fm @ vhf'], 'each poll replaces the objects, but nothing is pushed again');
    const kept = anomalies;
    anomalies = [];
    await f.tick(15000);
    anomalies = kept;
    await f.tick(15000);
    assert.deepEqual(sdrEvents(), ['dmr @ uhf', 'fm @ vhf', 'dmr @ uhf', 'fm @ vhf'], 'a returning anomaly is news again');
});

test('re-evaluation shows the server summary and dismisses only the anomalies it resolved', async () => {
    const reevaluated = [
        { id: 1, signal_class: 'dmr', node_id: 'a', anomaly_score: 0.9, reeval: { still_anomalous: true } },
        { id: 2, signal_class: 'fm', node_id: 'b', anomaly_score: 0.6, reeval: { still_anomalous: false } },
        { signal_class: 'fm', node_id: 'c', anomaly_score: 0.4, reeval: { still_anomalous: false } },
        { id: 4, signal_class: 'p25', node_id: 'd', anomaly_score: 0.3, reeval: { still_anomalous: false } }];
    let reeval = { anomalies: reevaluated, reeval_summary: { still_anomalous: 1, resolved: 3 } };
    let dismiss = {};
    const f = panel({ routes: (url, opts) => {
        if (url.startsWith('/api/detections/anomalies?limit=50&reevaluate=true')) return reeval;
        if (url === '/api/detections/anomalies/bulk/dismiss' && opts.method === 'PUT') return dismiss;
        return undefined;
    } });
    await f.tick(2000);
    change(f, f.el('rf-anomaly-group-select'), 'node_id');
    const button = f.el('rf-reeval-all-btn'), resolved = f.el('rf-dismiss-resolved-btn'), bar = f.el('rf-reeval-summary');
    assert.equal(bar.style.display, 'none');
    button.click();
    assert.deepEqual([button.disabled, button.textContent], [true, 'Evaluating...']);
    await settle();
    assert.deepEqual([button.disabled, button.textContent], [false, 'Re-evaluate All']);
    assert.deepEqual(bar.querySelectorAll('.reeval-badge').map(el => el.textContent), ['1 still anomalous', '3 resolved']);
    assert.deepEqual([bar.style.display, resolved.style.display], ['', '']);
    assert.equal(cards(f).length, 4);

    f.answerConfirm(false);
    resolved.click();
    assert.equal(f.writes().length, 0);
    assert.equal(f.dialogs.at(-1)[1], 'Dismiss 2 resolved anomalies?', 'only anomalies with a stored ID are offered');
    f.answerConfirm(true);
    reeval = { anomalies: [reevaluated[0]], reeval_summary: { still_anomalous: 1, resolved: 0 } };
    resolved.click();
    await settle();
    assert.equal(f.lastWrite().url, '/api/detections/anomalies/bulk/dismiss');
    assert.deepEqual(f.body(f.lastWrite()), { ids: [2, 4] });
    assert.ok(f.toasts().includes('Dismissed 2 resolved anomalies'));
    assert.equal(urls(f, '/api/detections/anomalies?limit=50&reevaluate=true').length, 2, 'the queue is re-evaluated again');
    assert.equal(resolved.style.display, 'none', 'nothing resolved is left to dismiss');
    // Resolved anomalies the server counted but sent without a row ID cannot be dismissed.
    reeval = { anomalies: [reevaluated[2]], reeval_summary: { still_anomalous: 0, resolved: 1 } };
    button.click();
    await settle();
    assert.equal(resolved.style.display, '');
    resolved.click();
    assert.ok(f.toasts().includes('No resolved anomalies to dismiss'));
    assert.equal(f.writes().length, 1);

    // Failures re-enable the controls and say so.
    reeval = { anomalies: reevaluated, reeval_summary: { still_anomalous: 1, resolved: 3 } };
    button.click();
    await settle();
    dismiss = NOT_JSON();
    resolved.click();
    await settle();
    assert.equal(f.toasts().at(-1), 'Bulk dismiss failed');
    reeval = new Error('offline');
    button.click();
    await settle();
    assert.equal(f.toasts().at(-1), 'Re-evaluation failed');
    assert.deepEqual([button.disabled, button.textContent], [false, 'Re-evaluate All']);
    reeval = {};
    button.click();
    await settle();
    assert.deepEqual([bar.style.display, resolved.style.display], ['none', 'none'], 'a reply without a summary hides it');
    assert.equal(f.el('anomaly-empty').style.display, '');
});

test('after re-evaluation, anomalies that are still active come first, by score, then the resolved ones', async () => {
    // Both groups peak at 0.9, so the grouped view keeps the re-evaluated order between them.
    const reply = { reeval_summary: { still_anomalous: 2, resolved: 1 }, anomalies: [
        { id: 1, signal_class: 'X', anomaly_score: 0.9, reeval: { still_anomalous: false } },
        { id: 2, signal_class: 'X', anomaly_score: 0.4, reeval: { still_anomalous: true } },
        { id: 3, signal_class: 'Y', anomaly_score: 0.9, reeval: { still_anomalous: true } }] };
    const f = panel({ routes: url => (url.startsWith('/api/detections/anomalies?limit=50&reevaluate=true') ? reply : undefined) });
    await f.tick(2000);
    change(f, f.el('rf-anomaly-group-select'), 'signal_class');
    f.el('rf-reeval-all-btn').click();
    await settle();
    assert.deepEqual(labels(f), [['Y', '1'], ['X', '2']], 'the server order would list X first');
});

test('Purge Resolved reports what the server dismissed and recovers from a failure', async () => {
    let purge = { dismissed: 3, still_anomalous: 1 };
    const f = panel({ routes: (url, opts) => (url === '/api/detections/anomalies/bulk/reeval-dismiss' && opts.method === 'POST' ? purge : undefined) });
    await f.tick(2000);
    const button = f.el('rf-purge-resolved-btn');
    const fetches = () => urls(f, '/api/detections/anomalies?limit=50&sort=').length;
    const before = fetches();
    button.click();
    assert.deepEqual([button.disabled, button.textContent], [true, 'Purging...']);
    await settle();
    assert.equal(f.toasts().at(-1), '3 resolved dismissed, 1 still active');
    assert.deepEqual([button.disabled, button.textContent], [false, 'Purge Resolved']);
    assert.equal(fetches(), before + 1, 'the queue is reloaded');
    assert.equal(f.lastWrite().headers['X-CSRF-Token'], 'csrf-abc123');
    purge = {};
    button.click();
    await settle();
    assert.equal(f.toasts().at(-1), '0 resolved dismissed, 0 still active');
    purge = new Error('bridge unreachable');
    button.click();
    await settle();
    assert.equal(f.toasts().at(-1), 'bridge unreachable');
    assert.deepEqual([button.disabled, button.textContent], [false, 'Purge Resolved']);
    purge = NOT_JSON();
    button.click();
    await settle();
    assert.equal(f.toasts().at(-1), 'HTTP 503');
});

test('Purge Resolved asks before dismissing anomalies server-side', async () => {
    const f = panel();
    await f.tick(2000);
    f.answerConfirm(false);
    f.el('rf-purge-resolved-btn').click();
    await settle();
    assert.equal(f.dialogs.filter(([kind]) => kind === 'confirm').length, 1);
    assert.equal(f.writes().length, 0);
});

test('the anomaly summary bar shows server counts, zeros for missing ones, and hides when empty', async () => {
    let summary = { total: 5, by_priority: { critical: 2, anomalous: 1, interesting: 2 }, unique_families: ['fsk', 'psk'], unique_nodes: ['a', 'b', 'c'] };
    const f = panel({ routes: url => (url.startsWith('/api/detections/anomalies/summary') ? summary : undefined) });
    const bar = f.el('rf-anomaly-summary');
    const texts = () => ['critical', 'anomalous', 'interesting', 'families', 'nodes'].map(name => f.el('rf-sum-' + name).textContent);
    assert.equal(bar.style.display, 'none');
    await f.tick(3000);
    assert.deepEqual(texts(), ['2 critical', '1 anomalous', '2 interesting', '2 families', '3 nodes']);
    assert.equal(bar.style.display, '');
    assert.ok(f.el('rf-sum-critical').classList.contains('rf-sum-critical-badge'));
    summary = new Error('offline');
    await f.tick(15000);
    assert.deepEqual(texts(), ['2 critical', '1 anomalous', '2 interesting', '2 families', '3 nodes'], 'a failed refresh keeps the last summary');
    summary = { total: 0 };
    await f.tick(15000);
    assert.deepEqual(texts(), ['0 critical', '0 anomalous', '0 interesting', '0 families', '0 nodes']);
    assert.equal(bar.style.display, 'none');
});

test('sorting, the scoring legend and the anomaly sparkline follow their controls and data', async () => {
    let timeline = [3];
    const f = panel({ activate: false, routes: url => (url.startsWith('/api/detections/anomalies?limit=50') ? { anomalies: [], timeline } : undefined) });
    const calls = chartCalls(f);
    f.dd.activate();
    await f.tick(2000);
    assert.equal(calls.drawSparkline.length, 0, 'one point is not a trend');
    timeline = [1, 4, 2];
    change(f, f.el('rf-anomaly-sort-select'), 'seen');
    await settle();
    assert.deepEqual(urls(f, '/api/detections/anomalies?limit=50'), ['/api/detections/anomalies?limit=50&sort=score',
        '/api/detections/anomalies?limit=50&sort=seen']);
    assert.equal(f.context.localStorage.getItem('bridge_rf_sort_by'), 'seen');
    assert.deepEqual(plain(calls.drawSparkline.at(-1)[2]), [1, 4, 2]);
    const body = f.el('anomaly-legend-body'), title = f.el('panel-anomalies').querySelector('.anomaly-legend-title');
    assert.equal(body.style.display, 'none');
    title.click();
    assert.equal(body.style.display, '');
    title.click();
    assert.equal(body.style.display, 'none');
});

test('the anomaly-scoring legend icon opens the legend', async () => {
    const f = panel();
    f.el('anomaly-legend-toggle').click();
    assert.equal(f.el('anomaly-legend-body').style.display, '');
});


/* Open the deep dive of one feed detection, the way an operator does: click its row. */
async function openFromFeed(f, signalClass) {
    const row = f.el('det-feed-tbody').querySelectorAll('.det-feed-row').find(r => r.getAttribute('data-dd-class') === signalClass);
    row.querySelectorAll('td')[3].click();
    await settle();
}
const fields = f => Object.fromEntries(f.el('dd-context').querySelectorAll('.dd-field')
    .map(field => [field.querySelector('.dd-field-label').textContent, field.querySelector('.dd-field-value').textContent]));

test('the deep dive shows receiver fields and captured IQ quality, or says it is a synthetic reference', async () => {
    const feed = [
        { detection_id: 'd-1', signal_class: 'lora', center_freq_hz: 915e6, power_db: -40.4, gain_db: 12, lna_state: 'high',
            has_iq_capture: true, node_id: 'edge-1', snr_db: 12, confidence: 0.9 },
        { signal_class: 'fm', snr_db: null }];
    let quality = { score: 0.6, clipped: true, dc_offset: true, phase_coherent: false };
    const features = Array.from({ length: 17 }, (_, i) => (i % 2 ? -i : i) / 10);
    const f = panel({ routes: url => {
        if (url.startsWith('/api/detections/recent?minutes=60&limit=50')) return { detections: feed };
        if (url.startsWith('/api/detections/d-1/iq?format=json')) return { constellation_x: [0.5, -1], constellation_y: [1, -2],
            psd_db: [-70, -80, -60], dsp_features: features };
        if (url.startsWith('/api/detections/d-1/iq/quality')) return quality;
        return undefined;
    } });
    await settle();
    const spectrogram = [];
    f.context.showSpectrogramForDetection = id => spectrogram.push('show ' + id);
    f.context.hideSpectrogramCard = () => spectrogram.push('hide');
    const drawn = Object.fromEntries(['constellation', 'psd', 'features', 'timedomain'].map(name => [name, canvasText(f.el('dd-' + name))]));
    const source = () => f.el('dd-iq-source');
    await openFromFeed(f, 'lora');
    assert.deepEqual([fields(f).Power, fields(f).Gain, fields(f).LNA, fields(f).Frequency, fields(f).Node],
        ['-40.4 dB', '12.0 dB', 'high', '915.00 MHz', 'edge-1']);
    assert.equal(source().querySelector('.iq-source-badge').textContent, 'Real Captured Waveform');
    assert.ok(source().querySelector('.iq-quality-badge').classList.contains('iq-quality-fair'));
    assert.ok(source().querySelector('.iq-quality-badge').textContent.startsWith('Quality: 60%'));
    assert.equal(source().querySelector('.iq-quality-warn').textContent, 'ADC clipped, DC offset, Phase incoherent');
    assert.deepEqual(spectrogram, ['show d-1']);
    assert.equal(f.el('dd-download-iq').style.display, '');
    // The captured waveform is drawn: constellation axes, PSD range, feature labels and both I/Q traces.
    assert.ok(drawn.constellation.includes('I') && drawn.constellation.includes('Q'));
    sameText(drawn.psd, ['-60 dB', '-80 dB', 'Frequency (normalized)']);
    assert.ok(['N2pk', 'F16', '1.60'].every(text => drawn.features.includes(text)), 'feature names and the largest value');
    sameText(drawn.timedomain, ['Sample Index', 'I', 'Q']);

    // iq_store.validate_iq_quality deducts 0.2 or 0.3 per defect, so 0.8 and 0.5 are real scores.
    for (const [answer, cls] of [[{ score: 0.9, phase_coherent: true }, 'iq-quality-good'], [{ score: 0.8, phase_coherent: true }, 'iq-quality-good'],
        [{ score: 0.5, phase_coherent: true }, 'iq-quality-fair'], [{ score: 0.3, phase_coherent: true }, 'iq-quality-poor'],
        [{ score: null }, null], [new Error('no quality'), null]]) {
        quality = answer;
        f.el('dd-close-btn').click();
        assert.equal(f.el('deep-dive-overlay').style.display, 'none');
        await openFromFeed(f, 'lora');
        const badge = source().querySelector('.iq-quality-badge');
        assert.equal(badge ? ['iq-quality-good', 'iq-quality-poor', 'iq-quality-fair'].find(c => badge.classList.contains(c)) : null, cls);
        assert.ok(!source().querySelector('.iq-quality-warn'), 'a coherent capture has no quality warning');
    }

    // A detection without an ID or IQ: synthetic reference, nothing to label or mark.
    spectrogram.length = 0;
    await openFromFeed(f, 'fm');
    assert.equal(source().textContent, 'Synthetic Reference');
    assert.ok(urls(f, '/api/signals/generate?').includes('/api/signals/generate?class=fm&snr=15&n=4096'), 'an unknown SNR asks for 15 dB');
    assert.equal(f.el('dd-feedback-group').style.display, 'none');
    assert.equal(f.el('dd-mark-known').style.display, 'none');
    assert.deepEqual(spectrogram, ['hide']);
    f.el('dd-capture-iq').click();
    assert.equal(f.toasts().at(-1), 'No node ID available for capture');
    f.el('deep-dive-body').click();
    assert.equal(f.el('deep-dive-overlay').style.display, '', 'a click inside the dialog keeps it open');
    f.el('deep-dive-overlay').click();
    assert.equal(f.el('deep-dive-overlay').style.display, 'none');
    assert.deepEqual(spectrogram, ['hide', 'hide']);
});

test('a failed IQ fetch falls back to the synthetic reference for that class and SNR', async () => {
    const f = panel({ routes: url => {
        if (url.startsWith('/api/detections/recent?minutes=60&limit=50')) return [{ detection_id: 'd-2', signal_class: 'dmr', snr_db: 7, has_iq_capture: true }];
        if (url.startsWith('/api/detections/d-2/iq?format=json')) return NOT_JSON();
        if (url.startsWith('/api/signals/generate?')) return { constellation_x: [0, 0], constellation_y: [0, 0], psd_db: [-70, -70], dsp_features: [0, 0] };
        return undefined;
    } });
    await settle();
    const drawn = Object.fromEntries(['constellation', 'psd', 'features', 'timedomain'].map(name => [name, canvasText(f.el('dd-' + name))]));
    await openFromFeed(f, 'dmr');
    assert.equal(f.el('dd-iq-source').textContent, 'Synthetic Reference');
    assert.equal(f.el('dd-download-iq').style.display, 'none', 'there is no capture to download');
    assert.ok(urls(f, '/api/signals/generate?').includes('/api/signals/generate?class=dmr&snr=7&n=4096'));
    // A flat reference still draws a readable scale instead of dividing by zero.
    sameText(drawn.psd, ['-69 dB', '-70 dB', 'Frequency (normalized)']);
    assert.ok(drawn.features.includes('1.00') && drawn.features.includes('0'));
    assert.ok(drawn.constellation.includes('I') && drawn.timedomain.includes('Sample Index'));
});

test('deep-dive actions: generate a reference, list the reporting nodes, export the class', async () => {
    let nodes = { detections: [{ node_id: 'a' }, { node_id: 'a' }, {}] };
    const f = panel({ routes: url => {
        if (url.startsWith('/api/detections/recent?minutes=60&limit=50')) return { detections: [{ detection_id: 'd-3', signal_class: 'lora', node_id: 'a' }] };
        if (url.startsWith('/api/detections/recent?minutes=60&limit=100')) return nodes;
        return undefined;
    } });
    await settle();
    const compared = [];
    f.db.nodeComparison = { show: list => compared.push([...list]) };
    await openFromFeed(f, 'lora');
    f.el('dd-gen-ref').click();
    await settle();
    assert.ok(urls(f, '/api/signals/generate?').includes('/api/signals/generate?class=lora&snr=20&n=4096'), 'a clean 20 dB reference');
    assert.equal(f.el('dd-iq-source').textContent, 'Synthetic Reference');
    f.el('dd-view-nodes').click();
    await settle();
    assert.deepEqual(f.dialogs.at(-1), ['alert', 'Detected on nodes: a']);
    assert.deepEqual([compared, f.el('deep-dive-overlay').style.display], [[], ''], 'one node is not a comparison');
    nodes = [];
    f.el('dd-view-nodes').click();
    await settle();
    assert.deepEqual(f.dialogs.at(-1), ['alert', 'Detected on nodes: none']);
    nodes = { detections: [{ node_id: 'a' }, { node_id: 'b' }] };
    f.el('dd-view-nodes').click();
    await settle();
    assert.deepEqual(compared, [['a', 'b']]);
    assert.equal(f.el('deep-dive-overlay').style.display, 'none', 'the comparison replaces the deep dive');
    nodes = NOT_JSON();
    f.el('dd-view-nodes').click();
    await settle();
    assert.equal(f.toasts().at(-1), 'Failed to load node data');
    f.el('dd-export').click();
    assert.equal(f.navigations.at(-1), 'open:/api/export/detections?class=lora&hours=1');
});

test('baseline comparison and the 48 h history accept every API shape and say when data is missing', async () => {
    let distribution = { classes: [{ name: 'fm' }, { class_name: 'lora' }] }, history = [{ count: 2 }, {}];
    const f = panel({ activate: false, routes: url => {
        if (url.startsWith('/api/detections/recent?minutes=60&limit=50')) return { detections: [{ detection_id: 'd-4', signal_class: 'lora' }] };
        if (url.startsWith('/api/detections/distribution?hours=24')) return distribution;
        if (url.startsWith('/api/detections/timeline?hours=48')) return history;
        return undefined;
    } });
    const calls = chartCalls(f);
    f.dd.activate();
    await settle();
    const baseline = f.el('dd-baseline');
    const reopen = async () => { f.el('deep-dive-close').click(); await openFromFeed(f, 'lora'); };
    await reopen();
    assert.equal(baseline.querySelector('.baseline-match').textContent, 'Match — lora is expected at this frequency');
    assert.deepEqual(baseline.querySelectorAll('.baseline-class-tag').map(tag => [tag.textContent, tag.classList.contains('match')]),
        [['fm', false], ['lora', true]]);
    assert.deepEqual(plain(calls.drawSparkline.at(-1)[2]), [2, 0]);
    distribution = [{ signal_class: 'fm' }];
    history = [];
    const cleared = calls.clearCanvas.length;
    await reopen();
    assert.equal(baseline.querySelector('.baseline-mismatch').textContent, 'Mismatch — lora is NOT expected at this frequency');
    assert.ok(calls.clearCanvas.slice(cleared).some(([, canvas]) => canvas === f.el('dd-history-sparkline')), 'an empty history clears the sparkline');
    distribution = {};
    await reopen();
    assert.equal(baseline.textContent, 'No baseline data for this frequency band');
    distribution = NOT_JSON();
    await reopen();
    assert.equal(baseline.textContent, 'Could not load baseline data');
});

test('the investigation checklist grades each check and recommends an action from the failures and warnings', async () => {
    const feed = [
        { signal_class: 'A', snr_db: 5, baseline_status: 'drift', anomaly_score: 0.5, confidence: 0.6, node_id: 'n1' },
        { signal_class: 'B', snr_db: 20, confidence: 0.9, has_iq_capture: true },
        { signal_class: 'C', snr_db: 20, baseline_status: 'learning', confidence: 0.95, has_iq_capture: true },
        { signal_class: 'D', snr_db: -5, baseline_status: 'drift', anomaly_score: 0.2, confidence: 0.9, has_iq_capture: true },
        { signal_class: 'E', snr_db: 20, baseline_status: 'drift', anomaly_score: 0.8, confidence: 0.9, has_iq_capture: true },
        { signal_class: 'F', has_iq_capture: true }];
    let others = { detections: [{ signal_class: 'A', node_id: 'n2' }, { signal_class: 'A', node_id: 'n3' }, { signal_class: 'A', node_id: 'n1' },
        { signal_class: 'B', node_id: 'n9' }, { signal_class: 'A' }] };
    const f = panel({ routes: url => {
        if (url.startsWith('/api/detections/recent?minutes=60&limit=50')) return { detections: feed };
        if (url.startsWith('/api/detections/recent?minutes=60&limit=200')) return others;
        return undefined;
    } });
    await settle();
    const stepEls = () => f.el('dd-investigation-checklist').querySelectorAll('.inv-step');
    const label = step => step.querySelector('.inv-step-label').textContent;
    const steps = () => stepEls().map(step => step.className.replace('inv-step inv-', ''));
    // Each graded step shows its grade's icon, the multi-node one once its check settles.
    const ICONS = { pass: '✔', warn: '⚠', fail: '✖', unknown: '—' };
    const wrongIcons = () => stepEls()
        .filter(step =>step.querySelector('.inv-step-icon').textContent !== ICONS[step.className.replace('inv-step inv-', '')]).map(label);
    const detail = name => stepEls().find(step => label(step) === name).querySelector('.inv-step-detail').textContent;
    const advice = () => f.el('dd-investigation-recommendation').querySelector('.inv-rec-action').textContent;
    const expected = {
        A: ['Investigate further', 'Multiple warnings — consider additional monitoring', ['warn', 'warn', 'warn', 'pass', 'warn', 'warn']],
        B: ['Dismiss', 'All checks nominal — likely benign or expected signal', ['pass', 'pass', 'pass', 'pass', 'pass', 'pass']],
        C: ['Add to baseline', 'All checks nominal — likely benign or expected signal', ['pass', 'warn', 'pass', 'warn', 'pass', 'pass']],
        D: ['Investigate further', 'One failure flag — review details before taking action', ['fail', 'pass', 'pass', 'warn', 'pass', 'warn']],
        E: ['Escalate', 'One failure flag — review details before taking action', ['pass', 'fail', 'pass', 'warn', 'pass', 'warn']],
        F: ['Dismiss', 'All checks nominal — likely benign or expected signal', ['unknown', 'pass', 'unknown', 'warn', 'pass', 'pass']],
    };
    for (const [cls, [action, threat, statuses]] of Object.entries(expected)) {
        await openFromFeed(f, cls);
        assert.equal(advice(), action, cls);
        assert.equal(detail('Threat Assessment'), threat, cls);
        assert.deepEqual(steps(), statuses, cls);
        assert.deepEqual(wrongIcons(), [], cls);
    }
    await openFromFeed(f, 'A');
    assert.equal(detail('Baseline Comparison'), 'Moderate deviation from baseline (score 0.50)');
    assert.equal(detail('Multi-Node Correlation'), 'Corroborated — also seen on 2 other nodes (n2, n3)');
    await openFromFeed(f, 'D');
    assert.equal(detail('Baseline Comparison'), 'Minor deviation (score 0.20)');
    assert.equal(detail('Multi-Node Correlation'), 'Single-node detection only — no corroboration from other sensors');
    others = NOT_JSON();
    await openFromFeed(f, 'A');
    assert.deepEqual([steps()[3], detail('Multi-Node Correlation')], ['unknown', 'Could not check other nodes']);
});

test('the multi-node check shows the icon of the grade it settles on', async () => {
    const f = panel({ routes: url => {
        if (url.startsWith('/api/detections/recent?minutes=60&limit=50')) return [{ signal_class: 'A', node_id: 'n1' }];
        if (url.startsWith('/api/detections/recent?minutes=60&limit=200')) return [{ signal_class: 'A', node_id: 'n2' }];
        return undefined;
    } });
    await settle();
    await openFromFeed(f, 'A');
    const step = f.el('inv-multi-node');
    assert.ok(step.classList.contains('inv-pass'));
    assert.equal(step.querySelector('.inv-step-icon').textContent, '✔');
});

test('analyst feedback reloads the queue when the server auto-dismisses, and reports a failure', async () => {
    let feedback = { auto_dismissed: true };
    const f = panel({ routes: (url, opts) => {
        if (url.startsWith('/api/detections/recent?minutes=60&limit=50')) return [{ detection_id: 'd-5', signal_class: 'dmr' }];
        if (url === '/api/detections/anomalies/d-5/feedback' && opts.method === 'POST') return feedback;
        return undefined;
    } });
    await settle();
    await openFromFeed(f, 'dmr');
    const loads = () => urls(f, '/api/detections/anomalies?limit=50').length;
    const before = loads();
    const button = label => f.el('dd-feedback-group').querySelector(`[data-feedback="${label}"]`);
    assert.equal(f.el('dd-feedback-group').style.display, '');
    button('true_positive').click();
    await settle();
    assert.deepEqual(f.body(f.lastWrite()), { label: 'true_positive' });
    assert.equal(f.toasts().at(-1), 'Feedback: true positive');
    assert.equal(loads(), before + 1, 'an auto-dismissed anomaly leaves the queue at once');
    feedback = { auto_dismissed: false };
    button('expected').click();
    await settle();
    assert.equal(loads(), before + 1);
    feedback = NOT_JSON();
    button('interesting').click();
    await settle();
    assert.equal(f.toasts().at(-1), 'Failed to submit feedback');
});

const shortTime = iso => new Date(iso).toLocaleString(undefined, { hour12: false, month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });

test('the IQ inventory formats sizes, sample counts, tiers and queue status, and filters by node, class and tier', async () => {
    const captured = clock(8, 15), queued = clock(8, 20);
    let stats = { total_captures: 3, total_size_bytes: 5 * 1048576, by_tier: { critical: 1, standard: 1, temporary: 1 } };
    let rows = [
        { detection_id: 'det-0123456789abcdef', node_id: 'n1', signal_class: 'dmr', tier: 'critical', freq_hz: 446e6, n_samples: 2500000,
            file_size_bytes: 3 * 1073741824, quality_score: 0.876, captured_at: captured },
        { detection_id: 'd2', node_id: 'n2', signal_class: 'lora', tier: 'temporary', n_samples: 2048, file_size_bytes: 2048 },
        { detection_id: 'd3', node_id: 'n2', n_samples: 512, file_size_bytes: 512, quality_score: 0 },
        {}];
    let commands = [{ command: 'iq_capture', node_id: 'n1', status: 'dispatched', params: { freq_hz: 433.92e6 }, queued_at: queued },
        { command: 'iq_capture', node_id: 'n2', status: 'done', params: { duration_ms: 500 } }, { command: 'iq_capture', node_id: 'n3' }, { command: 'iq_capture', node_id: 'n4', status: 'queued' }];
    const f = panel({ routes: url => {
        if (url.startsWith('/api/iq/stats')) return stats;
        if (url.startsWith('/api/iq/index')) return rows;
        if (url.startsWith('/api/nodes/commands')) return commands;
        return undefined;
    } });
    await f.tick(4000);
    const stat = name => f.el('iq-stat-' + name).textContent;
    assert.deepEqual(['total', 'size', 'critical', 'standard', 'temporary'].map(stat), ['3', '5.0 MB', '1', '1', '1']);
    assert.equal(f.el('iq-captures-badge').textContent, '3');
    const table = () => f.el('iq-captures-tbody').querySelectorAll('tr').map(tr => tr.querySelectorAll('td').slice(0, 9).map(td => td.textContent));
    assert.deepEqual(table(), [
        ['det-01234567', 'n1', '446.000 MHz', 'dmr', '2.5M', '3.00 GB', '88%', 'critical', shortTime(captured)],
        ['d2', 'n2', '--', 'lora', '2.0K', '2.0 KB', '--', 'temporary', '--'],
        ['d3', 'n2', '--', '--', '512', '512 B', '0%', 'standard', '--'],
        ['', '--', '--', '--', '--', '--', '--', 'standard', '--']]);
    assert.equal(f.el('iq-captures-tbody').querySelector('td').getAttribute('title'), 'det-0123456789abcdef', 'the full ID stays available');
    assert.deepEqual(f.el('iq-captures-tbody').querySelectorAll('tr').map(tr => tr.querySelectorAll('td')[7].querySelector('span').style.color),
        ['var(--accent-red)', 'var(--text-secondary)', 'var(--accent-yellow)', 'var(--accent-yellow)']);
    const queueRows = () => f.el('iq-commands-list').querySelectorAll('tbody tr');
    assert.deepEqual(queueRows().map(tr => tr.querySelectorAll('td').map(td => td.textContent)),
        [['n1', '433.920 MHz', '--', 'dispatched', shortTime(queued)], ['n2', '--', '500 ms', 'done', '--'], ['n3', '--', '--', '', '--'],
            ['n4', '--', '--', 'queued', '--']]);
    assert.deepEqual(queueRows().map(tr => tr.querySelectorAll('td')[3].querySelector('span').style.color),
        ['var(--accent-blue)', 'var(--accent-green)', 'var(--accent-green)', 'var(--accent-yellow)']);

    // The discovered nodes and classes become filters, and each filter narrows the next request.
    assert.deepEqual(f.el('iq-filter-node').options.map(o => o.value), ['', 'n1', 'n2']);
    assert.deepEqual(f.el('iq-filter-class').options.map(o => o.value), ['', 'dmr', 'lora']);
    change(f, f.el('iq-filter-node'), 'n2');
    change(f, f.el('iq-filter-class'), 'lora');
    change(f, f.el('iq-filter-tier'), 'temporary');
    await settle();
    assert.equal(urls(f, '/api/iq/index').at(-1), '/api/iq/index?limit=100&node_id=n2&signal_class=lora&tier=temporary');

    stats = { total_size_bytes: -1 };
    rows = [];
    commands = null;
    const before = [urls(f, '/api/iq/stats').length, urls(f, '/api/nodes/commands').length];
    f.el('iq-refresh').click();
    await settle();
    assert.deepEqual([urls(f, '/api/iq/stats').length, urls(f, '/api/nodes/commands').length], before.map(n => n + 1));
    assert.deepEqual(['total', 'size', 'critical', 'standard', 'temporary'].map(stat), ['0', '--', '0', '0', '0']);
    assert.equal(f.el('iq-captures-tbody').textContent, '');
    assert.equal(f.el('iq-captures-empty').style.display, '');
    assert.equal(f.el('iq-commands-list').textContent, 'No pending captures');
    stats = { total_size_bytes: 0 };
    f.el('iq-refresh').click();
    await settle();
    assert.equal(stat('size'), '0 B');
});

test('View on an IQ capture opens the deep dive of that capture', async () => {
    const f = panel({ routes: url => {
        if (url.startsWith('/api/iq/index')) return [{ detection_id: 'd-7', node_id: 'n1', signal_class: 'dmr' }];
        if (url.startsWith('/api/detections/d-7/iq')) return { detection_id: 'd-7', signal_class: 'dmr', constellation_x: [1], constellation_y: [0] };
        return undefined;
    } });
    await f.tick(4000);
    f.el('iq-captures-tbody').querySelector('[data-iq-view]').click();
    await settle();
    assert.equal(f.el('deep-dive-overlay').style.display, '');
    assert.equal(f.el('dd-mark-known').style.display, '', 'the deep dive knows which detection it shows');
    assert.ok(f.el('dd-iq-source').textContent.startsWith('Real Captured Waveform'));
});

test('View on an IQ capture shows that capture\'s class, node and frequency from the inventory row', async () => {
    const f = panel({ routes: url => {
        if (url.startsWith('/api/iq/index')) return [{ detection_id: 'd-1', node_id: 'n1', signal_class: 'lora' },
            { detection_id: 'd-9', node_id: 'n4', signal_class: 'p25', freq_hz: 851e6 }];
        if (url.startsWith('/api/detections/d-9/iq')) return { constellation_x: [1], constellation_y: [0] };
        return undefined;
    } });
    await f.tick(4000);
    f.el('iq-captures-tbody').querySelectorAll('[data-iq-view]')[1].click();
    await settle();
    assert.equal(f.el('deep-dive-title').textContent, 'Deep-Dive: p25');
    assert.equal(fields(f).Node, 'n4');
    assert.notEqual(fields(f).Frequency, '--');
    assert.ok(f.requests.some(call => call.url.startsWith('/api/detections/d-9/iq?format=json')), 'the captured IQ of that detection is drawn');
});

test('a failed IQ detail load is reported and opens nothing', async () => {
    const f = panel({ routes: url => {
        if (url.startsWith('/api/iq/index')) return [{ detection_id: 'd-8', node_id: 'n1' }];
        if (/^\/api\/detections\/d-8\/iq(\?_t=\d+)?$/.test(url)) return new Error('offline');
        return undefined;
    } });
    await f.tick(4000);
    f.el('iq-captures-tbody').querySelector('[data-iq-view]').click();
    await settle();
    assert.equal(f.toasts().at(-1), 'Failed to load IQ data: offline');
    assert.equal(f.el('deep-dive-overlay').style.display, 'none');
});
