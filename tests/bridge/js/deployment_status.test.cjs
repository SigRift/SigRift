const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const source = path.resolve(__dirname, '../../../src/sigrift/bridge/static/deployment.js');
const settle = () => new Promise(resolve => setImmediate(resolve));

function controller() {
    const elements = new Map(['deploy-table-wrap', 'deploy-empty', 'deploy-cache-info', 'deploy-refresh-btn']
        .map(id => [id, {innerHTML: '', textContent: '', style: {}, disabled: false,
            addEventListener() {}, querySelectorAll() { return []; }}]));
    const esc = value => String(value).replace(/[&<>"']/g, char => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    })[char]);
    const escaped = [];
    const context = {document: {getElementById: id => elements.get(id)},
        console, esc: value => { escaped.push(String(value)); return esc(value); }, fmtTime: value => value || 'unknown', fmtUptime: String};
    vm.runInNewContext(fs.readFileSync(source, 'utf8'), context, {filename: source});
    let response;
    const requests = [];
    const panel = new context.DeploymentPanel({apiFetch: url => {
        requests.push(url);
        return response instanceof Error ? Promise.reject(response) : Promise.resolve(response);
    }});
    return {panel, elements, requests, escaped, set: value => {response = value;},
        html: () => elements.get('deploy-table-wrap').innerHTML,
        status: () => elements.get('deploy-cache-info')};
}

const result = nodes => ({cached: false, cached_at: '2026-11-08T03:00:00Z', cache_ttl_sec: 300, nodes});

test('an all-failed fresh audit is not a green successful scan', () => {
    const c = controller();
    c.panel._render(result({edge: {reachable: false, ssh_status: 'host_key_unverified',
        error: 'SSH host identity has not been verified.'}}));
    assert.doesNotMatch(c.status().style.color, /success|22c55e/);
    assert.doesNotMatch(c.status().textContent, /Fresh scan/);
    assert.match(c.status().textContent, /0 verified/);
    assert.match(c.status().textContent, /1 failed/);
});

test('a reporting scanner with no SSH target is not presented as an offline node', () => {
    const c = controller();
    c.panel._render(result({'local-edge': {reachable: false, ssh_status: 'not_configured',
        node_status: 'online', last_seen: '2026-11-08T03:00:00Z', scanner_status: {
            sdr: {state: 'running', active: true, expires_in_seconds: 110}
        }, guidance: 'SSH auditing is optional; scanner reports do not require it.'}}));
    assert.match(c.html(), /SSH audit not configured/);
    assert.match(c.html(), /SDR: reporting/);
    assert.doesNotMatch(c.html(), />offline</);
    assert.doesNotMatch(c.html(), /deploy-update-btn|deploy-restart-btn/);
});

test('a failed HTTP refresh clears a previous successful status and restores the button', async () => {
    const c = controller();
    c.panel._render(result({edge: {reachable: true, ssh_status: 'verified'}}));
    c.set(new Error('status service unavailable'));
    c.panel.refresh(true); await settle();
    assert.match(c.status().textContent, /Refresh failed/);
    assert.doesNotMatch(c.status().style.color, /success|22c55e/);
    assert.match(c.html(), /status service unavailable/);
    assert.equal(c.elements.get('deploy-refresh-btn').disabled, false);
    assert.deepEqual(c.requests, ['/api/nodes/deployment?refresh=true']);
});

test('empty node inventory clears an earlier audit timestamp', () => {
    const c = controller();
    c.panel._render(result({edge: {reachable: true}}));
    c.panel._render(result({}));
    assert.equal(c.status().textContent, 'No registered nodes');
    assert.equal(c.html(), '');
});

test('failed-audit details are escaped and cannot inject controls', () => {
    const c = controller();
    c.panel._render(result({edge: {reachable: false, error: '<img src=x onerror=alert(1)>'}}));
    assert.doesNotMatch(c.html(), /<img/);
    assert.doesNotMatch(c.html(), /deploy-update-btn|deploy-restart-btn/);
});

test('a successful SSH audit retains the existing operator command controls', () => {
    const c = controller();
    c.panel._render(result({edge: {reachable: true, ssh_status: 'verified'}}));
    assert.match(c.html(), /deploy-update-btn/);
    assert.match(c.html(), /deploy-restart-btn/);
});

test('SSH failure never colors the node heading as failed or hides a live scanner', () => {
    const c = controller();
    c.panel._render(result({edge: {reachable: false, ssh_status: 'host_key_changed',
        node_status: 'active', error: 'SSH host identity changed.',
        scanner_status: {wifi: {state: 'running', active: true}}}}));
    assert.doesNotMatch(c.html(), /deploy-node-err|deploy-node-ok/);
    assert.match(c.html(), /Wi-Fi: reporting/);
    assert.match(c.html(), /SSH host identity changed/);
});

test('cached host audits render expired, error and recovered scanner reports separately', () => {
    const c = controller();
    for (const [state, active, text] of [['running', false, 'report expired'],
        ['error', false, 'error reported'], ['stopped', false, 'stopped'], ['running', true, 'reporting']]) {
        c.panel._render({...result({edge: {reachable: true, ssh_status: 'verified',
            scanner_status: {sdr: {state, active}}}}), cached: true});
        assert.match(c.html(), new RegExp('SDR: ' + text));
        assert.match(c.status().textContent, /host audit cached/);
    }
});

test('scanner report reasons use fixed wording and unknown codes keep the error wording', () => {
    const c = controller();
    for (const [reason, text] of [['starting', 'starting capture'], ['sensor_absent', 'sensor not connected'],
        ['sensor_changed', 'different sensor connected'], ['sensor_unusable', 'sensor cannot be opened'], ['capture_failed', 'error reported'], [null, 'error reported'],
        ['usb_gremlins', 'error reported'], ['constructor', 'error reported']]) {
        c.panel._render(result({edge: {reachable: false, ssh_status: 'not_configured', scanner_status: {
            sdr: {state: 'error', active: false, reason}, adsb: {state: 'error', active: false, reason}}}}));
        assert.match(c.html(), new RegExp('SDR: ' + text + '<br>ADS-B: ' + text + '<'));
        assert.doesNotMatch(c.html(), /usb_gremlins|function/);
    }
});

test('scanner report cells escape a node id with markup and their own text', () => {
    const c = controller(), id = '<img src=x onerror=alert(1)>';
    c.panel._render(result({[id]: {reachable: false, ssh_status: 'not_configured', scanner_status: {
        sdr: {state: 'error', active: false, reason: 'sensor_unusable'}}}}));
    assert.doesNotMatch(c.html(), /<img/);
    assert.match(c.html(), /<th>&lt;img src=x onerror=alert\(1\)&gt;/);
    // No node value reaches the report text, so check that it is escaped too.
    assert.ok(c.escaped.includes('SDR: sensor cannot be opened'));
});
