const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const source = path.resolve(__dirname, '../../../src/sigrift/bridge/static/detections.js');
const settle = () => new Promise(resolve => setImmediate(resolve));

function controller(stats, feed = []) {
    const text = new Map(), requests = [], errors = [], timers = new Map();
    let serial = 0, visible = true;
    const context = {console, window: {}, document: {addEventListener() {}},
        setText: (id, value) => text.set(id, String(value)),
        trackFetchError: (id, error) => errors.push([id, error.message]),
        setLoadingState() {}, isPageActive: () => visible,
        setTimeout: () => ++serial, clearTimeout() {},
        setInterval: (callback, delay) => {timers.set(++serial, {callback, delay}); return serial;},
        clearInterval: id => timers.delete(id)};
    vm.runInNewContext(fs.readFileSync(source, 'utf8'), context, {filename: source});
    const ui = Object.create(context.DetectionDashboard.prototype);
    Object.assign(ui, {feed, timeRange: 1, autoRefresh: true, paused: false, _active: false,
        db: {apiFetch: async url => {
            requests.push(url);
            if (!url.startsWith('/api/detections/stats?')) return {count: 0};
            if (stats instanceof Error) throw stats;
            return stats;
        }}});
    return {ui, text, requests, timers, errors,
        setStats: value => {stats = value;}, setVisible: value => {visible = value;}};
}

for (const [label, feed] of [['empty initial feed', []], ['limited recent feed', [{freq_hz: 515200000}, {freq_hz: 515200001}]]]) {
    test(`server hour count is independent of ${label}`, async () => {
        const c = controller({active_frequencies: 17, unique_classes: 6, avg_confidence: .91, detections_per_second: 2.4}, feed);
        c.ui._fetchKPIs(); await settle();
        assert.equal(c.text.get('det-kpi-freqs'), '17');
        assert.equal(c.text.get('det-kpi-rate'), '2.4/sec');
        assert.equal(c.text.get('det-kpi-classes'), '6');
        assert.equal(c.text.get('det-kpi-confidence'), '91%');
    });
}

test('a quiet hour displays a measured zero despite older feed rows', async () => {
    const c = controller({active_frequencies: 0}, [{freq_hz: 433920000}]);
    c.ui._fetchKPIs(); await settle();
    assert.equal(c.text.get('det-kpi-freqs'), '0');
});

for (const value of [undefined, null, -1, 1.5, '17', true, Infinity, Number.MAX_SAFE_INTEGER + 1]) {
    test(`invalid server frequency count ${String(value)} stays unavailable`, async () => {
        const c = controller({active_frequencies: value}, [{freq_hz: 433920000}]);
        c.ui._fetchKPIs(); await settle();
        assert.equal(c.text.get('det-kpi-freqs'), '--');
    });
}

test('changing the chart window does not infer a different frequency window from the feed', async () => {
    const c = controller({active_frequencies: 3}, [{freq_hz: 433920000}]);
    c.ui.timeRange = 24;
    c.ui._fetchKPIs(); await settle();
    assert.ok(c.requests.includes('/api/detections/stats?hours=24'));
    assert.equal(c.text.get('det-kpi-freqs'), '3');
});

test('the existing chart timer refreshes KPIs and respects pause, visibility and deactivation', async () => {
    const c = controller({active_frequencies: 1});
    let charts = 0;
    for (const method of ['_fetchFeed', '_fetchAnomalies', '_fetchAnomalySummary', '_initIQCaptures']) c.ui[method] = () => {};
    c.ui._fetchCharts = () => {charts++;};
    c.ui.activate(); await settle();
    assert.equal(c.text.get('det-kpi-freqs'), '1');
    assert.equal(c.timers.size, 4, 'reuse existing timers');
    const tick = c.timers.get(c.ui._pollCharts).callback;
    c.setStats({active_frequencies: 2}); tick(); await settle();
    assert.equal(c.text.get('det-kpi-freqs'), '2');
    assert.equal(charts, 1);
    const count = c.requests.length;
    for (const [property, value] of [['paused', true], ['autoRefresh', false]]) {
        const old = c.ui[property]; c.ui[property] = value; tick(); await settle();
        assert.equal(c.requests.length, count); c.ui[property] = old;
    }
    c.setVisible(false); tick(); await settle(); assert.equal(c.requests.length, count);
    c.setVisible(true); c.ui.deactivate(); tick(); await settle();
    assert.equal(c.timers.size, 0); assert.equal(c.requests.length, count);
});

test('a failed stats read remains observable and the next refresh recovers', async () => {
    const c = controller(new Error('offline'));
    c.ui._fetchKPIs(); await settle();
    assert.deepEqual(c.errors, [['det-kpis', 'offline']]);
    c.setStats({active_frequencies: 0}); c.ui._fetchKPIs(); await settle();
    assert.equal(c.text.get('det-kpi-freqs'), '0');
});
