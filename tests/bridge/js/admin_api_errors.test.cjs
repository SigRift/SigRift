/* Real HTTP responses through the shipped administrator API client. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const filename = path.resolve(__dirname, '../../../src/sigrift/bridge/static/admin.js');

async function client(t, { status = 500, body, contentType = 'application/json', retryAfter } = {}) {
    const requests = [], redirects = [], timers = [], toasts = [];
    const storage = new Map([['bridge_session_token', 'synthetic-session'], ['bridge_admin_key', 'synthetic-admin']]);
    const server = http.createServer((req, res) => {
        requests.push({ method: req.method, path: req.url });
        req.resume();
        res.writeHead(status, {
            'Content-Type': contentType, 'Connection': 'close',
            ...(retryAfter === undefined ? {} : { 'Retry-After': retryAfter }),
        });
        res.end(body === undefined ? '' : body);
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve())));
    const origin = 'http://127.0.0.1:' + server.address().port;
    const context = vm.createContext({
        console, Date, FormData,
        document: { addEventListener() {}, getElementById() { return null; } },
        window: { location: { replace: url => redirects.push(url) }, showToast: (msg, type) => toasts.push({ msg, type }) },
        sessionStorage: { getItem: name => storage.get(name), removeItem: name => storage.delete(name) },
        setTimeout: (fn, delay) => timers.push({ fn, delay }),
        fetch: (url, options) => fetch(origin + url, options),
    });
    vm.runInContext(fs.readFileSync(filename, 'utf8'), context, { filename });
    const panel = Object.create(context.AdminPanel.prototype);
    panel.apiKey = '';
    return { panel, requests, redirects, timers, storage, toasts };
}

for (const detail of [
    'Could not create a complete pre-restore backup; configuration was not changed.',
    'Configuration restore was incomplete. Restored: detection_config.json. Failed: alert_config.json.',
]) {
    test('restore HTTP failure retains its actionable server explanation: ' + detail, async t => {
        const c = await client(t, { body: JSON.stringify({ detail }) });
        await assert.rejects(c.panel.apiFetch('/api/admin/config-snapshots/7/restore', { method: 'POST' }), error => {
            assert.equal(error.status, 500);
            assert.equal(error.message, 'HTTP 500');
            assert.equal(error.detail, detail);
            return true;
        });
        assert.deepEqual(c.requests, [{ method: 'POST', path: '/api/admin/config-snapshots/7/restore' }]);
        assert.equal(c.timers.length, 0);
        assert.equal(c.redirects.length, 0);
        assert.equal(c.storage.get('bridge_session_token'), 'synthetic-session');
    });
}

test('rate-limited mutation keeps HTTP status, Retry-After and detail without replay', async t => {
    const c = await client(t, { status: 429, retryAfter: '30', body: JSON.stringify({ detail: 'Please wait before restoring again.' }) });
    await assert.rejects(c.panel.apiFetch('/api/admin/config-snapshots/7/restore', { method: 'POST' }), error => {
        assert.equal(error.status, 429);
        assert.equal(error.retryAfter, 30);
        assert.equal(error.detail, 'Please wait before restoring again.');
        return true;
    });
    assert.equal(c.requests.length, 1);
    assert.equal(c.timers.length, 0);
});

for (const body of ['', '{broken', 'null', '[]', '{}', '{"detail":null}', '{"detail":42}', '{"detail":[{"msg":"invalid"}]}']) {
    test('malformed or structured error remains an HTTP failure: ' + JSON.stringify(body), async t => {
        const c = await client(t, { status: 422, body });
        await assert.rejects(c.panel.apiFetch('/api/admin/detection-config', { method: 'PUT', body: {} }), error => {
            assert.equal(error.status, 422);
            assert.equal(error.message, 'HTTP 422');
            assert.equal(error.detail, undefined);
            return true;
        });
        assert.equal(c.requests.length, 1);
        assert.equal(c.redirects.length, 0);
    });
}

test('non-JSON error bodies are not presented as actionable JSON details', async t => {
    const c = await client(t, { status: 503, contentType: 'text/html', body: '<h1>upstream unavailable</h1>' });
    await assert.rejects(c.panel.apiFetch('/api/admin/config-snapshots'), error => error.status === 503 && error.message === 'HTTP 503' && error.detail === undefined);
});

for (const status of [401, 403]) {
    test('authentication failure ' + status + ' still clears credentials and redirects', async t => {
        const c = await client(t, { status, body: JSON.stringify({ detail: 'This body must not change authentication handling.' }) });
        await assert.rejects(c.panel.apiFetch('/api/admin/config-snapshots'), error => error.status === status && error.message === 'Unauthorized' && error.detail === undefined);
        assert.equal(c.storage.size, 0);
        assert.deepEqual(c.redirects, ['/login?next=%2Fadmin']);
        assert.equal(c.requests.length, 1);
    });
}

test('successful JSON response and no-content response retain their API contracts', async t => {
    const successful = await client(t, { status: 200, body: JSON.stringify({ status: 'restored', restored_files: ['detection_config.json'] }) });
    assert.deepEqual(await successful.panel.apiFetch('/api/admin/config-snapshots/7/restore', { method: 'POST' }), { status: 'restored', restored_files: ['detection_config.json'] });
    const empty = await client(t, { status: 204 });
    assert.equal(await empty.panel.apiFetch('/api/nodes/synthetic', { method: 'DELETE' }), null);
});

test('certificate listing failure shows the server reason instead of an empty list', async t => {
    const detail = 'The CA registry /srv/data/ca/registry.json is not valid JSON.';
    const c = await client(t, { status: 503, body: JSON.stringify({ detail }) });
    let rendered = false;
    c.panel._renderCerts = () => { rendered = true; };
    await c.panel._loadCerts();
    assert.deepEqual(c.requests, [{ method: 'GET', path: '/api/ca/certs' }]);
    assert.equal(rendered, false);
    assert.deepEqual(c.toasts, [{ msg: 'Could not load client certificates: ' + detail, type: 'error' }]);
});

test('certificate listing failure without a detail still says it failed', async t => {
    const c = await client(t, { status: 500, contentType: 'text/html', body: '<h1>oops</h1>' });
    await c.panel._loadCerts();
    assert.deepEqual(c.toasts, [{ msg: 'Could not load client certificates: HTTP 500', type: 'error' }]);
});

test('certificate listing authentication failure only redirects to the login page', async t => {
    const c = await client(t, { status: 401, body: JSON.stringify({ detail: 'expired' }) });
    await c.panel._loadCerts();
    assert.deepEqual(c.redirects, ['/login?next=%2Fadmin']);
    assert.deepEqual(c.toasts, []);
});
