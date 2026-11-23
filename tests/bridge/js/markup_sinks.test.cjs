/* Every way the shipped static pages turn data into markup, one class of sink
 * at a time: the escaping helpers themselves (text, double- and single-quoted
 * attributes), counts and other "numbers" that arrive as strings, values used
 * to look up elements, map popups, and the panels whose rows were built from
 * raw strings. Each case
 * stores hostile text where the page reads it and requires it to come back as
 * text, with no element or attribute it carried. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const parse5 = require('parse5');
const { bootDashboard, response, injected, settle } = require('./untrusted_dom.cjs');

const ROOT = path.resolve(__dirname, '../../..');
const STATIC_DIRS = ['src/sigrift/bridge/static', 'src/sigrift/lib/shiny/static'];
const MARKUP = '<img src=x onerror=alert(1)><script>alert(2)</script>';
// Closes a double-quoted attribute, a single-quoted one, or a JS string.
const QUOTE = 'x" onmouseover="alert(3)" data-x=\'y\' onfocus=\'alert(4)';

/* ------------------------------------------------------------------ */
/* The escaping helpers                                                */
/* ------------------------------------------------------------------ */

const HELPER = /function\s+(esc|_[A-Za-z]*Esc|_escText)\s*\(/g;

function staticFiles() {
    return STATIC_DIRS.flatMap(dir => fs.readdirSync(path.join(ROOT, dir))
        .filter(name => name.endsWith('.js')).map(name => `${dir}/${name}`));
}

/* The source of `function name(...) { ... }` starting at `at`. */
function functionSource(source, at) {
    let depth = 0;
    for (let i = source.indexOf('{', at); i < source.length; i++) {
        if (source[i] === '{') depth++;
        else if (source[i] === '}' && --depth === 0) return source.slice(at, i + 1);
    }
    throw new Error('unbalanced function at ' + at);
}

function helpers() {
    return staticFiles().flatMap(file => {
        const source = fs.readFileSync(path.join(ROOT, file), 'utf8');
        return [...source.matchAll(HELPER)].map(match => ({ file, name: match[1], source: functionSource(source, match.index) }));
    });
}

test('every static page escapes with a helper that is tested here', () => {
    assert.deepEqual(helpers().map(h => `${h.file.replace(/^src\/sigrift\//, '')}:${h.name}`).sort(), [
        'bridge/static/admin.js:esc', 'bridge/static/chart_utils.js:_escText', 'bridge/static/dashboard.js:esc',
        'bridge/static/incidents.js:esc', 'bridge/static/signals.js:_sigEsc', 'bridge/static/spectrum.js:_specEsc',
        'bridge/static/spectrum_analysis.js:_saEsc', 'bridge/static/threats.js:esc',
        'lib/shiny/static/dashboard.js:esc', 'lib/shiny/static/signals.js:_sigEsc',
        'lib/shiny/static/spectrum.js:_specEsc',
    ]);
    // Serialising a text node escapes & < > but never a quote: no page may
    // escape that way again.
    for (const file of staticFiles()) {
        const source = fs.readFileSync(path.join(ROOT, file), 'utf8');
        assert.doesNotMatch(source, /(createTextNode\([^;]*\)\)|\.textContent\s*=[^;]*);\s*return\s+\w+\.innerHTML/, file);
    }
});

for (const helper of helpers()) {
    test(`${helper.file.replace(/^src\/sigrift\//, '')} ${helper.name}() is safe in text and in either quoted attribute`, () => {
        const context = vm.createContext({ String });
        const escape = vm.runInContext(`(${helper.source})`, context);
        assert.equal(escape(`<a href="x">'&'</a>`), '&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;');
        assert.equal(escape(null), '');
        assert.equal(escape(undefined), '');
        assert.equal(escape(0), '0');
        for (const value of [MARKUP, QUOTE, '&amp; &lt;b&gt; &#39;', 'plain text']) {
            const html = `<div title="${escape(value)}" data-x='${escape(value)}'>${escape(value)}</div>`;
            const [div] = parse5.parseFragment(html).childNodes;
            assert.deepEqual(div.attrs, [{ name: 'title', value }, { name: 'data-x', value }], value);
            assert.equal(div.childNodes.length, 1, value);
            assert.equal(div.childNodes[0].value, value, value);
        }
    });
}

/* ------------------------------------------------------------------ */
/* Counts and other numbers that arrive as strings                     */
/* ------------------------------------------------------------------ */

// A count with markup and both quotes, for text and attribute positions alike.
const COUNT = QUOTE + MARKUP;

test('counts the API reports as strings render as text in the Summary frequency and node panels', async () => {
    const freqs = [
        { freq_mhz: 433.92, count: COUNT, classes: 'fm', nodes: 'edge-1', avg_power_dbm: -10 },
        // UHF Mil: listed as suspicious, so its count reaches that panel too.
        { freq_mhz: 300, count: COUNT, classes: 'mil', nodes: 'a,b', avg_power_dbm: -61 }];
    const node = { node_id: 'edge-1', host: 'h', status: 'active', capabilities: {},
        detection_summary: { total_detections: 1, period_seconds: 60, class_counts: { fm: COUNT } } };
    const f = bootDashboard({
        ids: ['tbody:active-freqs-tbody', 'active-freqs-badge', 'unique-freqs-grid', 'suspicious-freqs-list', 'tbody:nodes-tbody'],
        routes: url => {
            if (url.startsWith('/api/status')) return { node_count: 1, active_frequency_list: freqs };
            if (url.startsWith('/api/nodes/?')) return [node];
            return undefined;
        },
    });
    await settle();
    const active = f.el('active-freqs-tbody');
    assert.ok(active.querySelectorAll('td').some(cell => cell.textContent === COUNT), 'the count is shown as sent');
    assert.ok(f.el('unique-freqs-grid').textContent.includes(COUNT), 'band totals keep the reported text');
    const suspicious = f.el('suspicious-freqs-list').querySelectorAll('.suspicious-freq-meta span').map(span => span.textContent);
    assert.ok(suspicious.includes(COUNT + ' det'), suspicious.join(' | '));
    const bar = f.el('nodes-tbody').querySelector('.node-class-bar');
    assert.equal(bar.getAttribute('title'), 'fm: ' + COUNT);
    assert.equal(bar.querySelector('em').textContent, COUNT);
    for (const id of ['active-freqs-tbody', 'unique-freqs-grid', 'suspicious-freqs-list', 'nodes-tbody']) {
        assert.deepEqual(injected(f.el(id)), [], id);
    }
});

test('activity entries, stored HTML-encoded once, show the text that was logged', async () => {
    // state.log_activity() stores each field as Python's html.escape() writes it.
    const once = text => text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;').replace(/'/g, '&#x27;');
    const logged = { node_id: 'edge"1', event_type: 'wifi_<alert>',
        message: 'WiFi auto-alert: anomaly score 0.95 for Joe\'s "Cafe" & <b>Bar</b>' };
    const f = bootDashboard({
        ids: ['tbody:activity-log', 'activity-empty'],
        routes: url => (url.startsWith('/api/nodes/activity') ? [{ timestamp: new Date().toISOString(),
            node_id: once(logged.node_id), event_type: once(logged.event_type), message: once(logged.message) }] : undefined),
    });
    await settle();
    const log = f.el('activity-log');
    const row = log.querySelector('.activity-entry');
    assert.deepEqual(['node', 'type', 'msg'].map(name => row.querySelector('.activity-' + name).textContent),
        [logged.node_id, logged.event_type, logged.message]);
    assert.deepEqual(injected(log), []);
});

test('an unchanged scanner warning is left in place, also for a node ID with quotes', async () => {
    const node = `edge"'1`;
    const f = bootDashboard({
        ids: ['scanner-warning', 'scanner-warning-list'],
        routes: url => (url.startsWith('/api/nodes/?') ? [{ node_id: node, status: 'active', capabilities: {}, scanner_status: {
            wifi: { protocol: 'wifi', state: 'stopped', active: false, expires_in_seconds: 0, reported_at: new Date().toISOString() } } }] : undefined),
    });
    await settle();
    const list = f.el('scanner-warning-list');
    const [warning] = list.querySelectorAll('li');
    assert.equal(warning.querySelector('strong').textContent, node + ' · Wi-Fi — Scanner stopped');
    assert.equal(f.el('scanner-warning').hidden, false);
    // A poll with the same result must not rewrite the aria-live list:
    // a rewrite announces the warning again.
    f.db._renderScannerWarnings();
    assert.equal(list.querySelectorAll('li')[0], warning);
    assert.deepEqual(injected(list), []);
});

test('a loading error is shown as text', async () => {
    const f = bootDashboard({ ids: ['retry-box'] });
    await settle();
    f.context.setLoadingState('retry-box', false, MARKUP);
    assert.equal(f.el('retry-box').querySelector('p').textContent, MARKUP);
    assert.deepEqual(injected(f.el('retry-box')), []);
});

/* ------------------------------------------------------------------ */
/* Values used to find elements                                        */
/* ------------------------------------------------------------------ */

test('an alert ID with quotes and brackets acknowledges with its own note', async () => {
    const ids = [`a'1"]`, 'a-2'];
    const f = bootDashboard({
        ids: ['alerts-list', 'alerts-empty', 'alert-count-badge'],
        routes: (url, options) => {
            if (/^\/api\/alerts\/\?_t=/.test(url)) return ids.map(alert_id => ({ alert_id, severity: 'warning', message: 'm', acknowledged: false }));
            return options.method === 'PUT' ? {} : undefined;
        },
    });
    await settle();
    const list = f.el('alerts-list');
    const notes = list.querySelectorAll('[data-ack-note-for]');
    assert.deepEqual(notes.map(input => input.getAttribute('data-ack-note-for')), ids);
    notes[0].value = 'first';
    notes[1].value = 'second';
    list.querySelectorAll('[data-ack-alert]')[0].click();
    await settle();
    assert.equal(f.lastWrite().url, '/api/alerts/' + encodeURIComponent(ids[0]) + '/ack');
    assert.deepEqual(f.body(f.lastWrite()), { note: 'first' });
});

/* ------------------------------------------------------------------ */
/* Radio-reported tables and map popups (adsb.js, drone.js)            */
/* ------------------------------------------------------------------ */

function lease(protocol) {
    return { protocol, state: 'running', active: true, expires_in_seconds: 60, reported_at: new Date().toISOString() };
}

function leaflet(popups) {
    const layer = () => ({ addTo() { return this; }, setLatLng() {}, setStyle() {}, bindPopup(html) { popups.push(html); return this; } });
    return {
        map: () => ({ setView() { return this; }, invalidateSize() {}, removeLayer() {} }),
        tileLayer: () => ({ addTo() {} }),
        circleMarker: layer,
    };
}

/* Markup the page would hand Leaflet, parsed the way Leaflet inserts it. */
function popupElement(f, html) {
    const div = f.context.document.createElement('div');
    div.innerHTML = html;
    return div;
}

test('aircraft heard over the air render as text in the ADS-B table and map popups', async () => {
    const aircraft = { icao_address: QUOTE, callsign: MARKUP, source: MARKUP, last_seen: MARKUP, lat: 51.5, lon: -0.1, altitude_ft: 3000 };
    const f = bootDashboard({
        ids: ['table:aircraft-table', 'adsb-map', 'adsb-count'],
        routes: url => {
            if (url.startsWith('/api/nodes/?')) return [{ node_id: 'edge-1', status: 'active', capabilities: {}, scanner_status: { adsb: lease('adsb') } }];
            if (url.startsWith('/api/aircraft/')) return { aircraft: [aircraft] };
            return undefined;
        },
    });
    await settle();
    const tbody = f.add('aircraft-rows', 'tbody', f.el('aircraft-table'));
    const popups = [];
    f.context.L = leaflet(popups);
    f.load('adsb.js');
    await settle();
    assert.deepEqual(injected(tbody), []);
    const cells = tbody.querySelector('tr').querySelectorAll('td').map(cell => cell.textContent);
    assert.deepEqual([cells[0], cells[1], cells[2], cells[7]], [QUOTE, MARKUP, MARKUP, MARKUP]);
    f.context._adsbMapInvalidate();
    await f.tick(2000);
    assert.equal(popups.length, 1);
    const popup = popupElement(f, popups[0]);
    assert.deepEqual(injected(popup), []);
    assert.equal(popup.querySelector('b').textContent, MARKUP);
    assert.ok(popup.textContent.includes('ICAO: ' + QUOTE));
});

test('drone detections render sensor text as text', async () => {
    const f = bootDashboard({
        ids: ['table:drone-table'],
        routes: url => {
            if (url.startsWith('/api/nodes/?')) return [{ node_id: 'edge-1', status: 'active', capabilities: {}, scanner_status: { sdr: lease('sdr') } }];
            if (url.startsWith('/api/detections/recent?minutes=30')) return { detections: [{ signal_class: 'ELRS', timestamp: MARKUP, freq_hz: 868e6 }] };
            return undefined;
        },
    });
    await settle();
    const tbody = f.add('drone-rows', 'tbody', f.el('drone-table'));
    f.load('drone.js');
    await settle();
    assert.deepEqual(injected(tbody), []);
    const cells = tbody.querySelector('tr').querySelectorAll('td').map(cell => cell.textContent.trim());
    assert.deepEqual([cells[0], cells[4]], ['ELRS', MARKUP]);
});

/* ------------------------------------------------------------------ */
/* The same panels' other states, each still rendered as text          */
/* ------------------------------------------------------------------ */

test('ADS-B markers follow aircraft as text, sparse reports show blanks, and failures keep the table', async () => {
    let answer = { aircraft: [
        { icao_address: 'A1', callsign: 'LOW', lat: 1, lon: 1, altitude_ft: 1000, velocity_kts: 120, rssi_dbm: -40, source: 'mlat', last_seen: 't' },
        { icao_address: 'A2', lat: 2, lon: 2, altitude_ft: 10000 },
        { icao_address: 'A3', lat: 3, lon: 3, altitude_ft: 20000 },
        { icao_address: 'A4', lat: 4, lon: 4, altitude_ft: 40000 },
        { icao_address: 'A5', lat: 5, lon: 5 },
        { icao_address: MARKUP },
    ] };
    const f = bootDashboard({
        ids: ['table:aircraft-table', 'adsb-map', 'adsb-count'],
        routes: url => {
            if (url.startsWith('/api/nodes/?')) return [{ node_id: 'edge-1', status: 'active', capabilities: {}, scanner_status: { adsb: lease('adsb') } }];
            if (url.startsWith('/api/aircraft/')) return answer;
            return undefined;
        },
    });
    await settle();
    const tbody = f.add('aircraft-rows', 'tbody', f.el('aircraft-table'));
    const popups = [], moved = [], removed = [];
    const L = leaflet(popups);
    const marker = L.circleMarker;
    L.circleMarker = (at, style) => Object.assign(marker(), { style, setLatLng: next => moved.push(next) });
    L.map = () => ({ setView() { return this; }, invalidateSize() {}, removeLayer: layer => removed.push(layer) });
    f.context.L = L;
    f.load('adsb.js');
    f.context._adsbMapInvalidate();
    f.context._adsbMapInvalidate();
    await f.tick(2000);
    assert.equal(f.el('adsb-count').textContent, '6 aircraft');
    const rows = tbody.querySelectorAll('tr').map(row => row.querySelectorAll('td').map(cell => cell.textContent));
    assert.deepEqual(rows[0], ['A1', 'LOW', 'mlat', '1000 ft', '120 kts', '1.0000, 1.0000', '-40.0 dBm', 't']);
    assert.deepEqual(rows[1], ['A2', '', '', '10000 ft', '', '2.0000, 2.0000', '', '']);
    assert.equal(rows[5][0], MARKUP);
    assert.deepEqual(injected(tbody), []);
    assert.equal(popups.length, 5, 'only aircraft with a position get a marker');
    assert.ok(popups[1].includes('Spd: ?') && popups[1].includes('Source: ?'));
    // The next report moves a known aircraft and drops the ones no longer heard.
    answer = { aircraft: [{ icao_address: 'A1', lat: 9, lon: 9, altitude_ft: 1000 }] };
    await f.tick(2000);
    assert.deepEqual([...moved.at(-1)], [9, 9]);
    assert.equal(removed.length, 4);
    assert.equal(f.el('adsb-count').textContent, '1 aircraft');
    // A refused or failed request leaves the table as it was.
    for (const failure of [response(503, {}), new Error('offline')]) {
        answer = failure;
        await f.tick(2000);
        assert.equal(tbody.querySelectorAll('tr').length, 1);
    }
    answer = {};
    await f.tick(2000);
    assert.equal(f.el('adsb-count').textContent, '0 aircraft');
});

test('the drone tab lists only drone classes, with blanks for unreported fields', async () => {
    let answer = { detections: [
        { signal_class: 'DJI-OFDM', freq_hz: 2.4e9, power_dbm: -50, timestamp: 'now' },
        { signal_class: 'fpv_analog' },
        { signal_class: 'fm', timestamp: MARKUP },
        { timestamp: MARKUP },
    ] };
    const f = bootDashboard({
        ids: ['table:drone-table'],
        routes: url => {
            if (url.startsWith('/api/nodes/?')) return [{ node_id: 'edge-1', status: 'active', capabilities: {}, scanner_status: { sdr: lease('sdr') } }];
            if (url.startsWith('/api/detections/recent?minutes=30')) return answer;
            return undefined;
        },
    });
    await settle();
    const tbody = f.add('drone-rows', 'tbody', f.el('drone-table'));
    f.load('drone.js');
    await settle();
    const rows = tbody.querySelectorAll('tr').map(row => row.querySelectorAll('td').map(cell => cell.textContent.trim()));
    assert.deepEqual(rows, [
        ['DJI-OFDM', 'DJI-OFDM', '2400.0 MHz', '-50.0 dBm', 'now', 'now', 'Active'],
        ['fpv_analog', 'fpv_analog', '', '', '', '', 'Active']]);
    answer = {};
    await f.tick(5000);
    assert.equal(tbody.querySelectorAll('tr').length, 0);
    answer = new Error('offline');
    await f.tick(5000);
    assert.ok(f.warnings.some(text => text.startsWith('Drone refresh error')));
});

/* ------------------------------------------------------------------ */
/* Map popups (maps.js, geo_map.js)                                    */
/* ------------------------------------------------------------------ */

/* The Leaflet calls maps.js and geo_map.js make; every popup's markup is kept. */
function leafletPopups(popups) {
    const layer = () => ({
        addTo() { return this; }, bindPopup(html) { popups.push(html); return this; }, unbindPopup() {}, remove() {},
        on() {}, setLatLng() {}, setIcon() {}, dragging: { enable() {}, disable() {} },
    });
    return {
        map: () => ({ fitBounds() {}, invalidateSize() {}, remove() {}, on() {}, addLayer() {}, removeLayer() {} }),
        tileLayer: () => ({ addTo() { return this; } }),
        layerGroup: () => ({ addTo() { return this; }, clearLayers() {} }),
        divIcon: options => options,
        circleMarker: layer, marker: layer, polygon: layer, imageOverlay: layer,
    };
}

test('map viewer popups show node, emitter and zone text as text; floor plans are matched by ID as text', async () => {
    // IDs that end a quoted attribute selector: built into one, they throw.
    const listed = `plan"]'1`, added = `plan'"]2`;
    const f = bootDashboard({
        ids: ['map-view-container', 'select:map-floor-plan'],
        routes: url => {
            if (url === '/api/maps/overlay') return {
                nodes: [{ node_id: MARKUP, status: QUOTE, lat: 1, lon: 2 }],
                emitters: [{ emitter_id: QUOTE, lat: 3, lon: 4, confidence: 0.5 }],
                floor_plans: [{ id: listed, name: MARKUP }, { id: added, name: QUOTE }] };
            if (url === '/api/maps/floor-plans') return [{ id: listed, name: MARKUP }];
            if (url === '/api/maps/view/fp1') return {
                floor_plan: { width_px: 100, height_px: 80 },
                nodes: [{ node_id: QUOTE, x: 1, y: 2 }],
                emitters: [{ emitter_id: MARKUP, x: 3, y: 4 }],
                zones: [{ name: MARKUP, zone_type: QUOTE, polygon: [[0, 0], [1, 0], [1, 1]] }] };
            return undefined;
        },
    });
    await settle();
    const popups = [];
    f.context.L = leafletPopups(popups);
    f.load('maps.js');
    const viewer = vm.runInContext("new MapViewer('map-view-container')", f.context);
    await viewer.init();
    const shown = () => popups.splice(0).map(html => {
        const popup = popupElement(f, html);
        assert.deepEqual(injected(popup), [], html);
        return popup.textContent;
    });
    assert.deepEqual(shown(), ['Node: ' + MARKUP + 'Status: ' + QUOTE, 'Emitter: ' + QUOTE + 'Confidence: 0.50']);
    // The floor-plan list keeps the plans it lists; the overlay adds only a
    // plan it does not list yet, matched by its exact ID.
    const select = f.el('map-floor-plan');
    assert.deepEqual(select.options.map(option => option.value), ['', listed]);
    await viewer.loadOverlay();
    assert.deepEqual(select.options.map(option => [option.value, option.textContent]),
        [['', 'Outdoor Map'], [listed, MARKUP], [added, QUOTE]]);
    shown();
    await viewer.loadFloorPlan('fp1');
    assert.deepEqual(shown(), ['Node: ' + QUOTE, 'Emitter: ' + MARKUP + 'Confidence: 0.00', MARKUP + 'Type: ' + QUOTE]);
});

test('geo map popups show a node\'s location, signals and reported counts as text', async () => {
    const f = bootDashboard({
        ids: ['geo-map-container', 'geo-node-count-badge', 'geo-map-empty'],
        scripts: ['geo_map.js'],
        routes: url => (url.startsWith('/api/geo/map?') ? [{ node_id: 'edge-1', status: 'active', latitude: 1, longitude: 2,
            location_name: MARKUP, detection_count_1h: MARKUP, anomaly_count_1h: QUOTE, top_signals: [MARKUP, QUOTE] }] : undefined),
    });
    await settle();
    const popups = [];
    f.context.L = leafletPopups(popups);
    f.db.geoMap.init();
    await settle();
    assert.equal(popups.length, 1);
    const popup = popupElement(f, popups[0]);
    assert.deepEqual(injected(popup), []);
    assert.equal(popup.querySelector('em').textContent, MARKUP);
    assert.deepEqual(popup.querySelectorAll('strong').map(el => el.textContent), ['edge-1', MARKUP, QUOTE]);
    assert.ok(popup.textContent.includes('Top signals: ' + MARKUP + ', ' + QUOTE), popup.textContent);
    assert.equal(f.el('geo-node-count-badge').textContent, '1 nodes');
});

/* ------------------------------------------------------------------ */
/* RF Intelligence (detections.js)                                     */
/* ------------------------------------------------------------------ */

const RF_IDS = ['tbody:det-feed-tbody', 'det-feed-empty', 'det-count-badge', 'anomaly-queue', 'anomaly-empty',
    'anomaly-count-badge', 'stat-anomaly-detail', 'select:rf-anomaly-group-select', 'select:rf-anomaly-filter-key',
    'select:rf-anomaly-filter-val', 'rf-bulk-bar', 'rf-bulk-count', 'input:rf-select-all', 'button:rf-bulk-dismiss',
    'button:rf-bulk-escalate', 'button:rf-bulk-export', 'button:rf-reeval-all-btn', 'button:rf-dismiss-resolved-btn',
    'rf-reeval-summary', 'tbody:iq-captures-tbody', 'iq-captures-empty', 'select:iq-filter-node', 'select:iq-filter-class'];

function rfPanel(routes) {
    const f = bootDashboard({ ids: RF_IDS, scripts: ['chart_utils.js', 'detections.js'], routes: (url, options) => {
        const answer = routes(url, options);
        if (answer !== undefined) return answer;
        if (url.startsWith('/api/detections/recent')) return { count: 0, detections: [] };
        if (url.startsWith('/api/detections/anomalies?')) return { anomalies: [], total: 0 };
        return options.method && options.method !== 'GET' ? {} : undefined;
    } });
    f.dd = f.db.detectionDashboard;
    return f;
}

test('an RF anomaly without a row ID is dismissed by its exact detection ID', async () => {
    const detection = 'd/1" onmouseover="alert(5)';
    const f = rfPanel(url => (url.startsWith('/api/detections/anomalies?') ? { anomalies: [
        { detection_id: detection, signal_class: 'dmr', anomaly_score: 0.9, timestamp: new Date().toISOString() }], total: 1 } : undefined));
    // Every queue section renders its cards with _renderAnomalyQueueFlat,
    // which reads `s` before its `var s = this` (the known TypeError held
    // in detections_rendering.test.cjs). Bind it first, as that fix does,
    // so this escape is pinned today; the extra declaration is harmless
    // once the fix lands.
    const proto = f.context.DetectionDashboard.prototype;
    proto._renderAnomalyQueueFlat = vm.runInContext(
        '(' + proto._renderAnomalyQueueFlat.toString().replace('{', '{ var s = this;') + ')', f.context);
    f.dd.activate();
    await f.tick(5000);
    const queue = f.el('anomaly-queue');
    assert.deepEqual(injected(queue), []);
    const dismiss = queue.querySelector('[data-dismiss-rf]');
    assert.equal(dismiss.getAttribute('data-dismiss-rf'), detection);
    dismiss.click();
    await settle();
    assert.equal(f.lastWrite().url, '/api/detections/anomalies/' + encodeURIComponent(detection) + '/dismiss');
});

test('IQ capture sample counts and RF re-evaluation counts render as text', async () => {
    const f = rfPanel(url => {
        if (url.startsWith('/api/iq/index?limit=100&')) return [{ detection_id: 'd-1', node_id: 'edge-1', n_samples: MARKUP, tier: 'standard' }];
        if (url.startsWith('/api/detections/anomalies?limit=50&reevaluate=true&')) {
            return { anomalies: [], reeval_summary: { still_anomalous: MARKUP, resolved: QUOTE } };
        }
        return undefined;
    });
    f.dd.activate();
    await f.tick(5000);
    const captures = f.el('iq-captures-tbody');
    assert.deepEqual(injected(captures), []);
    assert.equal(captures.querySelector('tr').querySelectorAll('td')[4].textContent, MARKUP);
    f.el('rf-reeval-all-btn').click();
    await settle();
    const summary = f.el('rf-reeval-summary');
    assert.deepEqual(injected(summary), []);
    assert.deepEqual(summary.querySelectorAll('.reeval-badge').map(badge => badge.textContent),
        [MARKUP + ' still anomalous', QUOTE + ' resolved']);
});

/* ------------------------------------------------------------------ */
/* Wi-Fi re-evaluation (wifi.js)                                       */
/* ------------------------------------------------------------------ */

test('Wi-Fi re-evaluation counts render as text', async () => {
    const f = bootDashboard({
        ids: ['wifi-anomaly-queue', 'wifi-anomaly-empty', 'wifi-anomaly-count-badge', 'button:wifi-reeval-all-btn', 'wifi-reeval-summary'],
        scripts: ['wifi.js'],
        routes: url => (url.startsWith('/api/wifi/anomalies?min_score=0.3&limit=50&reevaluate=true&')
            ? { anomalies: [], total: 0, reeval_summary: { still_anomalous: MARKUP, resolved: QUOTE } } : undefined),
    });
    await settle();
    f.el('wifi-reeval-all-btn').click();
    await settle();
    const summary = f.el('wifi-reeval-summary');
    assert.deepEqual(injected(summary), []);
    assert.deepEqual(summary.querySelectorAll('.reeval-badge').map(badge => badge.textContent),
        [MARKUP + ' still anomalous', QUOTE + ' resolved']);
});

/* ------------------------------------------------------------------ */
/* Wideband peaks (spectrum_analysis.js)                               */
/* ------------------------------------------------------------------ */

test('a wideband peak keeps its reported frequency and class as data, flat or grouped', async () => {
    const f = bootDashboard({
        ids: ['tbody:wb-peaks-tbody', 'wb-peaks-empty', 'wb-peaks-badge'],
        routes: url => (url.startsWith('/api/spectrum/monitor/peaks?')
            ? { peaks: [{ freq_hz: QUOTE, node_id: MARKUP, signal_class: MARKUP, classified: false }] } : undefined),
    });
    await settle();
    // The Spectrum tab's own panel needs a MutationObserver; the peaks table does not.
    f.load('chart_utils.js', 'spectrum_analysis.js');
    const monitor = new f.context.WidebandMonitor(f.db);
    for (const groupBy of ['', 'frequency']) {
        monitor._peaksGroupBy = groupBy;
        monitor._loadPeaks();
        await settle();
        const tbody = f.el('wb-peaks-tbody');
        assert.deepEqual(injected(tbody), [], groupBy);
        const row = tbody.querySelector('.wb-peak-row');
        assert.deepEqual([row.getAttribute('data-peak-freq'), row.getAttribute('data-peak-class')], [QUOTE, MARKUP], groupBy);
        assert.equal(row.querySelector('[data-drilldown-peak-freq]').getAttribute('data-drilldown-peak-freq'), QUOTE, groupBy);
        assert.equal(row.querySelectorAll('td')[3].textContent, MARKUP, groupBy);
    }
});

/* ------------------------------------------------------------------ */
/* Deployment status (deployment.js)                                   */
/* ------------------------------------------------------------------ */

test('deployment: script hashes render as text and a node ID with quotes acts on its own buttons', async () => {
    const id = `edge"]'1`, other = 'edge-2';
    const audited = { reachable: true, ssh_status: 'verified', script_versions: { 'rf_scan.py': { hash: MARKUP } } };
    const f = bootDashboard({
        ids: ['deploy-table-wrap', 'deploy-empty', 'deploy-cache-info', 'button:deploy-refresh-btn'],
        scripts: ['deployment.js'],
        routes: (url, options) => {
            if (url.startsWith('/api/nodes/deployment')) return { generated_at: '2026-11-10T00:00:00Z', nodes: { [id]: audited, [other]: audited } };
            if (options.method === 'POST') return { status: 'queued' };
            return undefined;
        },
    });
    await settle();
    const panel = f.db.deploymentPanel;
    panel.refresh(true);
    await settle();
    const wrap = f.el('deploy-table-wrap');
    assert.deepEqual(injected(wrap), []);
    const hashes = wrap.querySelectorAll('td').filter(cell => cell.getAttribute('title') === MARKUP);
    assert.deepEqual(hashes.map(cell => cell.textContent), [MARKUP.substring(0, 8), MARKUP.substring(0, 8)]);
    const buttons = node => wrap.querySelectorAll('.deploy-update-btn, .deploy-restart-btn').filter(b => b.getAttribute('data-node') === node);
    assert.equal(buttons(id).length, 2);
    panel._sendCommand(buttons(id)[0].getAttribute('data-node'), 'update');
    await settle();
    assert.equal(f.lastWrite().url, '/api/nodes/' + encodeURIComponent(id) + '/command');
    assert.deepEqual(buttons(id).map(b => [b.disabled, b.textContent]), [[true, 'Queued'], [true, 'Queued']]);
    assert.deepEqual(buttons(other).map(b => [b.disabled, b.textContent]), [[false, 'Update'], [false, 'Restart']]);
});

/* ------------------------------------------------------------------ */
/* Threat signatures (threats.js)                                      */
/* ------------------------------------------------------------------ */

test('threat signatures: frequencies that are not numbers and a match count render as text, escaped once', async () => {
    const sig = { id: 'sig-1', name: 'Bug', threat_category: 'covert_mic', threat_level: 'high',
        freq_min_hz: MARKUP, freq_max_hz: QUOTE, center_freq_hz: '&amp;' };
    const f = bootDashboard({
        ids: ['tab-threats', 'tbody:threats-tbody', 'threats-empty', 'button:threat-refresh-btn'],
        routes: (url, options) => {
            if (url.startsWith('/api/signatures/threats/list')) return [sig];
            if (url === '/api/signatures/sig-1') return sig;
            if (url === '/api/signatures/threats/match' && options.method === 'POST') {
                return { matched: true, count: MARKUP, matches: [{ name: QUOTE, threat_level: 'high', match_score: 0.5 }] };
            }
            return undefined;
        },
    });
    await settle();
    f.context.MutationObserver = class { observe() {} };
    f.load('threats.js');
    f.el('threat-refresh-btn').click();
    await settle();
    const tbody = f.el('threats-tbody');
    const row = tbody.querySelector('tr[data-id]');
    assert.equal(row.querySelectorAll('td')[4].textContent, MARKUP + ' Hz - ' + QUOTE + ' Hz');
    row.click();
    await settle();
    assert.deepEqual(injected(tbody), []);
    const detail = f.document.getElementById('threat-detail-sig-1');
    for (const text of ['Freq Min: ' + MARKUP + ' Hz', 'Freq Max: ' + QUOTE + ' Hz', 'Center Freq: &amp; Hz']) {
        assert.ok(detail.textContent.includes(text), text);
    }
    f.document.getElementById('threat-test-btn-sig-1').click();
    await settle();
    const result = f.document.getElementById('threat-test-result-sig-1');
    assert.deepEqual(injected(result), []);
    assert.ok(result.textContent.startsWith(MARKUP + ' match(es) found:' + QUOTE + ' — '), result.textContent);
});
