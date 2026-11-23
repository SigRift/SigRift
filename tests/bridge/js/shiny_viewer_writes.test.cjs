/* Shiny dashboard: a write the key's role does not allow (403) is reported.
 *
 * Viewer keys (the default) are read-only on the server: alert, job and
 * evaluation writes need an analyst key, node commands an admin key, key
 * management the master key.  The shipped dashboard.js runs in a stub DOM
 * whose innerHTML is parsed by parse5; every write button is clicked and
 * the server answers with the given status through a stubbed fetch.
 */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const parse5 = require('parse5');

const root = path.resolve(__dirname, '../../..');
const source = path.join(root, 'src/sigrift/lib/shiny/static/dashboard.js');
const settle = async () => { for (let i = 0; i < 5; i++) await new Promise(resolve => setImmediate(resolve)); };

function attributes(node) { return Object.fromEntries((node.attrs || []).map(attr => [attr.name, attr.value])); }
function nodes(node, tag) {
    return [...(node.tagName === tag ? [node] : []), ...(node.childNodes || []).flatMap(child => nodes(child, tag))];
}
function text(node) {
    return node.nodeName === '#text' ? node.value : (node.childNodes || []).map(text).join('');
}

// An element whose innerHTML is parsed as a browser would; its buttons can
// be found by attribute (querySelectorAll('[data-...]')) and clicked.
function element(wrap = html => html) {
    let html = '', buttons = [], tree = null;
    const el = {
        value: '', textContent: '', style: {}, checked: false,
        get innerHTML() { return html; },
        set innerHTML(value) {
            html = value;
            tree = parse5.parseFragment(wrap(value));
            buttons = nodes(tree, 'button').map(node => {
                const attrs = attributes(node), events = {};
                return {attrs, getAttribute: name => attrs[name],
                    addEventListener(type, fn) { (events[type] ||= []).push(fn); },
                    click() { for (const fn of events.click || []) fn.call(this, {}); }};
            });
        },
        get text() { return tree ? text(tree) : ''; },
        get tags() { return tree ? new Set(nodes(tree, 'b').concat(nodes(tree, 'img')).map(n => n.tagName)) : new Set(); },
        querySelectorAll(selector) {
            const name = selector.replace(/^\[|\]$/g, '');
            return buttons.filter(b => Object.hasOwn(b.attrs, name));
        },
        addEventListener() {},
        focus() {},
    };
    return el;
}

function response(status, body, contentType = 'application/json') {
    return {
        status, ok: status >= 200 && status < 300,
        headers: {get: name => (name.toLowerCase() === 'content-type' ? contentType : null)},
        json: () => (body instanceof Error ? Promise.reject(body) : Promise.resolve(body)),
    };
}

function fixture({missing = []} = {}) {
    const table = html => '<table><tbody>' + html + '</tbody></table>';
    const els = {
        'nodes-tbody': element(table), 'models-tbody': element(table), 'jobs-tbody': element(table),
        'keys-tbody': element(table), 'alerts-list': element(),
        'nodes-empty': element(), 'alerts-empty': element(), 'alert-hide-acked': element(),
        'modal-title': element(), 'modal-body': element(), 'modal-overlay': element(),
        'auth-overlay': element(), 'auth-key-input': element(),
        'rule-name': element(), 'rule-severity': element(), 'job-name': element(),
        'job-preset': element(), 'job-priority': element(),
        'key-id-input': element(), 'key-desc-input': element(), 'key-node-input': element(),
        'key-role-input': element(),
    };
    for (const id of missing) delete els[id];
    const requests = [];
    let reply = () => response(200, {});
    const context = {
        console,
        FormData: class FormData {},
        confirm: () => true,
        sessionStorage: {getItem: () => 'viewer-key', setItem() {}},
        document: {
            addEventListener() {},
            getElementById: id => els[id] || null,
            createElement: () => {
                const el = {innerHTML: ''};
                el.appendChild = child => {
                    el.innerHTML += String(child.textContent)
                        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
                };
                return el;
            },
            createTextNode: value => ({textContent: value}),
        },
        fetch: (url, options) => {
            requests.push({url, method: options.method || 'GET', headers: options.headers, body: options.body});
            return Promise.resolve(reply(url, options));
        },
    };
    vm.runInNewContext(fs.readFileSync(source, 'utf8'), context, {filename: source});
    const db = Object.create(context.ShinyDashboard.prototype);
    db.apiKey = 'viewer-key';
    const reloads = [];
    for (const name of ['_loadAlerts', '_loadJobs', '_loadKeys']) db[name] = () => reloads.push(name);
    return {db, els, context, requests, reloads,
        answer(fn) { reply = fn; },
        modal: () => (els['modal-overlay'].style.display === '' ? {title: els['modal-title'].textContent,
            text: els['modal-body'].text, tags: els['modal-body'].tags} : null)};
}

const DENIED = '<b>analyst role required</b>';

// Every write button and form a viewer can reach, with the route it calls.
const WRITES = [
    {action: 'send node commands', url: '/api/nodes/edge-01/command', method: 'POST',
        run: f => { f.db._renderNodes([{node_id: 'edge-01', status: 'active'}]); f.els['nodes-tbody'].querySelectorAll('[data-cmd-node]')[0].click(); }},
    {action: 'queue model evaluations', url: '/api/training/models/edge-v1/evaluate', method: 'POST',
        run: f => { f.db._renderModels([{model_id: 'edge-v1', name: 'edge-v1.pth'}]); f.els['models-tbody'].querySelectorAll('[data-eval-model]')[0].click(); }},
    {action: 'acknowledge alerts', url: '/api/alerts/a1/ack', method: 'PUT', reload: '_loadAlerts',
        run: f => { f.db._renderAlerts([{alert_id: 'a1', message: 'm'}]); f.els['alerts-list'].querySelectorAll('[data-ack-alert]')[0].click(); }},
    {action: 'create alert rules', url: '/api/alerts/rules', method: 'POST', reload: '_loadAlerts',
        run: f => { f.els['rule-name'].value = 'cpu'; f.db._createRule(); }},
    {action: 'rerun jobs', url: '/api/jobs/j1/rerun', method: 'POST', reload: '_loadJobs',
        run: f => { f.db._renderJobs([{job_id: 'j1', name: 'j'}]); f.els['jobs-tbody'].querySelectorAll('[data-rerun-job]')[0].click(); }},
    {action: 'create jobs', url: '/api/jobs/', method: 'POST', reload: '_loadJobs',
        run: f => { f.els['job-name'].value = 'nightly'; f.db._createJob(); }},
    {action: 'rotate keys', url: '/api/keys/k1/rotate', method: 'PUT', reload: '_loadKeys',
        run: f => { f.db._renderKeys([{key_id: 'k1'}]); f.els['keys-tbody'].querySelectorAll('[data-rotate-key]')[0].click(); }},
    {action: 'revoke keys', url: '/api/keys/k1', method: 'DELETE', reload: '_loadKeys',
        run: f => { f.db._renderKeys([{key_id: 'k1'}]); f.els['keys-tbody'].querySelectorAll('[data-revoke-key]')[0].click(); }},
    {action: 'create keys', url: '/api/keys/', method: 'POST', reload: '_loadKeys',
        run: f => { f.els['key-id-input'].value = 'ops'; f.db._createKey(); }},
];

for (const write of WRITES) {
    test(`a refused write is reported: ${write.action}`, async () => {
        const f = fixture();
        f.answer(() => response(403, {detail: DENIED}));
        write.run(f); await settle();
        assert.deepEqual(f.requests.map(r => [r.url, r.method]), [[write.url, write.method]]);
        assert.equal(f.requests[0].headers['X-API-Key'], 'viewer-key');
        const modal = f.modal();
        assert.ok(modal, 'no notice for a 403');
        assert.equal(modal.title, 'Not permitted');
        // The server's detail is shown as text, never as markup.
        assert.match(modal.text, new RegExp(`This API key cannot ${write.action}: <b>analyst role required</b>\\.`));
        assert.match(modal.text, /Viewer keys are read-only/);
        assert.equal(modal.tags.size, 0);
        assert.deepEqual(f.reloads, []);
    });

    test(`other failures stay silent and a success reloads: ${write.action}`, async () => {
        for (const status of [404, 422, 500]) {
            const f = fixture();
            f.answer(() => response(status, {detail: 'x'}));
            write.run(f); await settle();
            assert.equal(f.requests.length, 1);
            assert.equal(f.modal(), null, `notice for a ${status}`);
        }
        const f = fixture();
        f.answer(() => response(200, {job_id: 'eval-1', raw_key: 'r', message: 'm'}));
        write.run(f); await settle();
        if (write.reload) assert.deepEqual(f.reloads, [write.reload]);
        const modal = f.modal();
        assert.notEqual(modal && modal.title, 'Not permitted');
    });
}

test('apiFetch rejects with the status and the server detail', async () => {
    const f = fixture();
    const outcome = p => p.then(v => ({ok: v}), e => ({status: e.status, detail: e.detail, message: e.message}));

    f.answer(() => response(403, {detail: 'analyst role required'}));
    assert.deepEqual(await outcome(f.db.apiFetch('/api/jobs/', {method: 'POST', body: {name: 'j'}})),
        {status: 403, detail: 'analyst role required', message: 'analyst role required'});
    assert.equal(f.requests[0].body, '{"name":"j"}');
    assert.equal(f.requests[0].headers['Content-Type'], 'application/json');

    // A validation error's detail is a list, and a body need not be JSON.
    f.answer(() => response(422, {detail: [{msg: 'bad'}]}));
    assert.deepEqual(await outcome(f.db.apiFetch('/api/jobs/')), {status: 422, detail: '', message: 'HTTP 422'});
    f.answer(() => response(502, new SyntaxError('not json'), 'text/html'));
    assert.deepEqual(await outcome(f.db.apiFetch('/api/jobs/')), {status: 502, detail: '', message: 'HTTP 502'});
    f.answer(() => response(500, null));
    assert.deepEqual(await outcome(f.db.apiFetch('/api/jobs/')), {status: 500, detail: '', message: 'HTTP 500'});

    // 401 asks for a key; success paths are unchanged.
    let asked = 0; f.db._showAuth = () => { asked++; };
    f.answer(() => response(401, {detail: 'Invalid API key'}));
    assert.equal((await outcome(f.db.apiFetch('/api/jobs/'))).message, 'Unauthorized');
    assert.equal(asked, 1);
    f.answer(() => response(200, [1]));
    assert.deepEqual((await outcome(f.db.apiFetch('/api/jobs/'))).ok, [1]);
    f.answer(() => response(204, null));
    assert.equal((await outcome(f.db.apiFetch('/api/jobs/'))).ok, null);
    const raw = response(200, null, 'text/csv');
    f.answer(() => raw);
    assert.equal((await outcome(f.db.apiFetch('/api/export/nodes'))).ok, raw);
});

test('_writeFailed reports only a 403, with a fallback detail', () => {
    const f = fixture();
    f.db._writeFailed('create jobs', undefined);
    f.db._writeFailed('create jobs', new Error('network'));
    f.db._writeFailed('create jobs', f.context.apiError(500, {detail: 'boom'}));
    assert.equal(f.modal(), null);
    f.db._writeFailed('create jobs', f.context.apiError(403, {}));
    assert.match(f.modal().text, /This API key cannot create jobs: permission denied\./);
});

test('the write forms send what was entered, and nothing when it is empty', async () => {
    const f = fixture();
    const bodies = () => f.requests.map(r => [r.url, JSON.parse(r.body)]);
    f.db._createRule(); f.db._createJob(); f.db._createKey();
    f.els['rule-name'].value = '   '; f.db._createRule();
    assert.deepEqual(f.requests, []);

    f.els['rule-name'].value = ' cpu '; f.els['rule-severity'].value = 'critical';
    f.els['job-name'].value = 'nightly'; f.els['job-preset'].value = 'fast'; f.els['job-priority'].value = '7';
    f.els['key-id-input'].value = 'ops'; f.els['key-desc-input'].value = ' d '; f.els['key-node-input'].value = 'edge-01';
    f.els['key-role-input'].value = 'analyst';
    f.db._createRule(); f.db._createJob(); f.db._createKey(); await settle();
    assert.deepEqual(bodies(), [
        ['/api/alerts/rules', {name: 'cpu', severity: 'critical', thresholds: {}}],
        ['/api/jobs/', {name: 'nightly', priority: 7, params: {}, preset: 'fast'}],
        ['/api/keys/', {key_id: 'ops', description: 'd', node_id: 'edge-01', role: 'analyst'}],
    ]);
    // Once the key is created the form is cleared, back to the least role.
    assert.deepEqual(['key-id-input', 'key-desc-input', 'key-node-input', 'key-role-input'].map(id => f.els[id].value),
        ['', '', '', 'viewer']);
    // A refused creation keeps what was entered.
    f.answer(() => response(403, {detail: 'Master key required'}));
    f.els['key-id-input'].value = 'ops2'; f.els['key-role-input'].value = 'admin';
    f.db._createKey(); await settle();
    assert.deepEqual(JSON.parse(f.requests.at(-1).body), {key_id: 'ops2', description: '', role: 'admin'});
    assert.deepEqual([f.els['key-id-input'].value, f.els['key-role-input'].value], ['ops2', 'admin']);

    const bare = fixture({missing: ['rule-severity', 'key-desc-input', 'key-node-input', 'key-role-input']});
    bare.els['rule-name'].value = 'cpu'; bare.els['job-name'].value = 'j'; bare.els['key-id-input'].value = 'ops';
    bare.db._createRule(); bare.db._createJob(); bare.db._createKey(); await settle();
    assert.deepEqual(bare.requests.map(r => JSON.parse(r.body)), [
        {name: 'cpu', severity: 'warning', thresholds: {}},
        {name: 'j', priority: 0, params: {}},
        {key_id: 'ops', description: ''},
    ]);
});

test('the panels with write buttons render every state', () => {
    const f = fixture();
    f.db._renderNodes([]);
    assert.equal(f.els['nodes-tbody'].innerHTML, '');
    assert.equal(f.els['nodes-empty'].style.display, '');
    f.db._renderNodes([
        {node_id: 'a', status: 'active', cpu_percent: 1.25, memory_mb: 512.4, classifications_per_sec: 3.33,
            capabilities: {agent_version: '1.2', pending_updates: 3, disk_percent: 50.55, cpu_temp: 61.4, load_1m: 0.5}},
        {node_id: 'b', status: 'stale', capabilities: {agent_version: '1.2', pending_updates: 0}},
        {node_id: 'c', capabilities: {agent_version: '1.2'}},
    ]);
    assert.equal(f.els['nodes-empty'].style.display, 'none');
    const html = f.els['nodes-tbody'].innerHTML;
    for (const want of ['mon-active', 'mon-stale', 'mon-offline', 'has-updates', '50.5%', '61°C', '0.50', '1.3', '512', '3.3', 'unknown']) {
        assert.ok(html.includes(want), want);
    }
    assert.deepEqual(f.els['nodes-tbody'].querySelectorAll('[data-cmd-node]').map(b => b.getAttribute('data-cmd-node')), ['a', 'b', 'c']);

    f.db._renderModels([]);
    assert.match(f.els['models-tbody'].innerHTML, /No models/);
    f.db._renderModels(null);
    assert.match(f.els['models-tbody'].innerHTML, /No models/);
    f.db._renderModels([{model_id: 'm', name: 'm.pth', size_bytes: 512}, {model_id: 'n', size_bytes: 2048},
        {model_id: 'o', size_bytes: 3 * 1048576}]);
    for (const want of ['512 B', '2.0 KB', '3.0 MB']) assert.ok(f.els['models-tbody'].innerHTML.includes(want), want);

    f.db._renderJobs([]);
    assert.match(f.els['jobs-tbody'].innerHTML, /No jobs/);

    const alerts = [{alert_id: 'a1', severity: 'critical', message: 'm1', acknowledged: true}, {alert_id: 'a2', message: 'm2'}];
    f.db._renderAlerts(alerts);
    assert.deepEqual(f.els['alerts-list'].querySelectorAll('[data-ack-alert]').map(b => b.getAttribute('data-ack-alert')), ['a2']);
    assert.ok(f.els['alerts-list'].innerHTML.includes('critical acknowledged'));
    assert.equal(f.els['alerts-empty'].style.display, 'none');
    f.els['alert-hide-acked'].checked = true;
    f.db._renderAlerts(alerts);
    assert.ok(!f.els['alerts-list'].innerHTML.includes('m1'));
    f.db._renderAlerts([alerts[0]]);
    assert.equal(f.els['alerts-list'].innerHTML, '');
    assert.equal(f.els['alerts-empty'].style.display, '');

    const none = fixture({missing: ['nodes-tbody', 'models-tbody', 'jobs-tbody', 'alerts-list', 'nodes-empty', 'alerts-empty']});
    for (const render of ['_renderNodes', '_renderModels', '_renderJobs', '_renderAlerts']) {
        assert.doesNotThrow(() => none.db[render]([{node_id: 'a', alert_id: 'a', job_id: 'a', model_id: 'a'}]), render);
    }
    const noEmpty = fixture({missing: ['nodes-empty', 'alerts-empty']});
    noEmpty.db._renderNodes([]); noEmpty.db._renderNodes([{node_id: 'a'}]);
    noEmpty.db._renderAlerts([]); noEmpty.db._renderAlerts([{alert_id: 'a'}]);
    assert.ok(noEmpty.els['nodes-tbody'].innerHTML.includes('mon-none'));
});
