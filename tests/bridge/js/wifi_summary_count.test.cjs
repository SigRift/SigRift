const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const source = path.resolve(__dirname, '../../../src/sigrift/bridge/static/dashboard.js');

function controller() {
    const elements = new Map(['sum-wifi-networks', 'sum-wifi-clients', 'sum-wifi-anomalies']
        .map(id => [id, {textContent: '--'}]));
    const timers = new Map(), listeners = new Map(), badges = [], requests = [], fresh = [];
    let nextTimer = 0, response = {total_networks: 8, total_clients: 24, anomaly_count: 0};
    const document = {hidden: false, getElementById: id => elements.get(id) || null,
        addEventListener: (event, callback) => listeners.set(event, callback)};
    const context = {document, window: {}, console,
        setInterval: (callback, delay) => { timers.set(++nextTimer, {callback, delay}); return nextTimer; },
        clearInterval: id => timers.delete(id)};
    vm.runInNewContext(fs.readFileSync(source, 'utf8'), context, {filename: source});
    const wifiSource = path.join(path.dirname(source), 'wifi.js');
    vm.runInNewContext(fs.readFileSync(wifiSource, 'utf8'), context, {filename: wifiSource});
    const dashboard = Object.create(context.BridgeDashboard.prototype);
    dashboard.pollTimers = {};
    // Only unrelated polling is suppressed; the shipped Summary/start/stop paths execute.
    dashboard._pollStatus = dashboard._pollNodes = dashboard._pollIngestStatus = () => {};
    dashboard._markSourceFresh = name => fresh.push(name);
    dashboard._updateTabBadge = (...args) => badges.push(args);
    dashboard.apiFetch = url => {
        requests.push(url);
        if (url !== '/api/wifi/stats') return Promise.resolve({});
        return response instanceof Error ? Promise.reject(response) : Promise.resolve(response);
    };
    const panel = Object.create(context.WifiPanel.prototype);
    panel.dashboard = dashboard;
    panel._updateReevalSummary = panel._renderWifiAnomalyQueue = () => {};
    return {dashboard, panel, timers, badges, requests, fresh,
        text: () => String(elements.get('sum-wifi-anomalies').textContent),
        set: value => {response = value;},
        tick: () => timers.get(dashboard.pollTimers.ss).callback(),
        hidden(value) {document.hidden = value; listeners.get('visibilitychange')();}};
}

const settle = () => new Promise(resolve => setImmediate(resolve));

test('Summary startup and its actual 30-second timer keep numeric zero without opening Wi-Fi', async () => {
    const c = controller();
    c.dashboard._startPolling(); await settle();
    assert.equal(c.text(), '0');
    assert.equal(c.timers.get(c.dashboard.pollTimers.ss).delay, 30000);
    c.tick(); await settle();
    assert.equal(c.text(), '0');
    assert.equal(c.requests.filter(url => url === '/api/wifi/stats').length, 2);
    assert.ok(!c.requests.some(url => url.includes('/anomalies')));
    assert.deepEqual(c.badges.filter(row => row[0] === 'wifi'), [['wifi', 0, ''], ['wifi', 0, '']]);
});

test('next Summary refresh displays the complete queue count and its later dismissal', async () => {
    const c = controller(); c.set({anomaly_count: 53});
    c.dashboard._startPolling(); await settle();
    assert.equal(c.text(), '53');
    assert.deepEqual(c.badges.find(row => row[0] === 'wifi'), ['wifi', 53, 'warning']);
    c.set({anomaly_count: 0}); c.tick(); await settle();
    assert.equal(c.text(), '0');
});

test('Wi-Fi list observation and the next Summary timer agree on the same API queue total', async () => {
    const c = controller();
    const fetch = c.dashboard.apiFetch;
    c.dashboard.apiFetch = url => url.includes('/wifi/anomalies?')
        ? Promise.resolve({total: 53, anomalies: Array.from({length: 50}, () => ({}))}) : fetch(url);
    c.set({anomaly_count: 53}); c.dashboard._startPolling(); await settle();
    c.panel._pollWifiAnomalies(); await settle();
    assert.equal(c.text(), '53');
    assert.equal(c.panel.wifiAnomalies.length, 50);
    c.tick(); await settle();
    assert.equal(c.text(), '53');
});

test('failed stats refresh retains the prior observed count and does not mark Wi-Fi fresh', async () => {
    const c = controller(); c.set({anomaly_count: 3});
    c.dashboard._startPolling(); await settle();
    c.set(new Error('Synthetic unavailable stats')); c.tick(); await settle();
    assert.equal(c.text(), '3');
    assert.equal(c.fresh.filter(name => name === 'wifi').length, 1);
    assert.equal(c.badges.filter(row => row[0] === 'wifi').length, 1);
});

test('legacy missing count is unknown, never invented as a displayed zero', async () => {
    const c = controller(); c.set({total_networks: 8});
    c.dashboard._startPolling(); await settle();
    assert.equal(c.text(), '--');
});

test('hidden-page polling pauses and resumes with the latest count', async () => {
    const c = controller(); c.dashboard._startPolling(); await settle();
    c.hidden(true); c.set({anomaly_count: 2}); c.tick(); await settle();
    assert.equal(c.text(), '0');
    assert.equal(c.requests.filter(url => url === '/api/wifi/stats').length, 1);
    c.hidden(false); c.tick(); await settle();
    assert.equal(c.text(), '2');
});

test('stopping polling removes the Summary timer', async () => {
    const c = controller(); c.dashboard._startPolling(); await settle();
    c.dashboard._stopPolling();
    assert.equal(c.timers.size, 0);
});
