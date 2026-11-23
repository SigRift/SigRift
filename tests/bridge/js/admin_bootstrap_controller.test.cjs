/* Exercise actual shipped admin bootstrap/API error handling, not copied logic. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const sourcePath = path.resolve(__dirname, '../../../src/sigrift/bridge/static/admin.js');
const source = fs.readFileSync(sourcePath, 'utf8');
const settle = () => new Promise(resolve => setImmediate(resolve));
function response(status = 200, retryAfter = null) {
    return { status, ok: status >= 200 && status < 300,
        headers: { get: name => name === 'Retry-After' ? retryAfter : name === 'content-type' ? 'application/json' : null },
        json: async () => { if (status >= 400) throw new Error('Non-JSON error body'); return {}; },
    };
}
function controller(responses) {
    const requests = [], redirects = [], timers = new Map();
    const storage = new Map([['bridge_admin_key', 'fixture-admin'], ['bridge_session_token', 'fixture-session']]);
    const text = { textContent: '' };
    const status = { className: '', querySelector: name => name === '.status-text' ? text : null };
    const retry = { hidden: true, onclick: null, style: { display: 'none' } };
    let timerId = 0;
    const context = { console, Date, FormData: class {},
        document: { addEventListener() {}, getElementById: id => id === 'admin-status' ? status : id === 'admin-auth-retry' ? retry : null },
        window: { location: { replace: url => redirects.push(url) } },
        sessionStorage: { getItem: name => storage.get(name), removeItem: name => storage.delete(name) },
        setTimeout: (callback, delay) => { timers.set(++timerId, { callback, delay }); return timerId; },
        fetch: async (url, opts) => {
            requests.push({ url, ...opts });
            assert.ok(responses.length, 'Unexpected network request');
            const next = responses.shift();
            if (next instanceof Error) throw next;
            return await next;
        },
    };
    vm.runInNewContext(source, context, { filename: sourcePath });
    const panel = Object.create(context.AdminPanel.prototype);
    panel.apiKey = ''; panel.authenticated = false;
    const calls = { user: 0, tick: 0, tab: 0, expired: 0 };
    panel._fetchAdminUserInfo = () => calls.user++;
    panel._startAdminSessionInfoTick = () => calls.tick++;
    panel._loadCurrentTab = () => calls.tab++;
    panel._renderSessionExpired = () => calls.expired++;
    return { panel, requests, redirects, timers, storage, text, retry, calls,
        async start() { panel._tryAuth(); await settle(); },
        async fireTimer() {
            assert.equal(timers.size, 1);
            const [id, timer] = timers.entries().next().value;
            timers.delete(id); timer.callback(); await settle();
        },
    };
}
function assertSessionPreserved(c) {
    assert.equal(c.redirects.length, 0);
    assert.equal(c.storage.get('bridge_admin_key'), 'fixture-admin');
    assert.equal(c.storage.get('bridge_session_token'), 'fixture-session');
    assert.equal(c.calls.expired, 0);
}

test('successful bootstrap initializes its user/session/tab once', async () => {
    const c = controller([response()]); await c.start();
    assert.equal(c.panel.authenticated, true);
    assert.equal(c.text.textContent, 'Authenticated');
    assert.deepEqual(c.calls, { user: 1, tick: 1, tab: 1, expired: 0 });
    c.panel._tryAuth(); await settle();
    assert.equal(c.requests.length, 1, 'Completed bootstrap cannot initialize twice');
    assert.equal(c.retry.style.display, 'none');
    assertSessionPreserved(c);
});

for (const status of [401, 403]) test(`real HTTP ${status} still clears credentials and redirects`, async () => {
    const c = controller([response(status)]); await c.start();
    assert.deepEqual(c.redirects, ['/login?next=%2Fadmin']);
    assert.equal(c.storage.size, 0);
    assert.equal(c.calls.expired, 1);
    assert.equal(c.calls.tab, 0);
    assert.equal(c.timers.size, 0);
});

for (const seconds of [1, 59, 60]) test(`429 honors ${seconds}s Retry-After once without losing session`, async () => {
    const c = controller([response(429, String(seconds)), response()]); await c.start();
    assertSessionPreserved(c);
    assert.equal(c.requests.length, 1);
    assert.equal(c.timers.values().next().value.delay, seconds * 1000);
    assert.match(c.text.textContent, /rate limited/i);
    assert.equal(c.retry.hidden, true);
    c.panel._tryAuth(); await settle();
    assert.equal(c.requests.length, 1, 'Pending retry cannot be duplicated');
    await c.fireTimer();
    assert.equal(c.requests.length, 2);
    assert.ok(c.requests.every(r => r.url === '/api/admin/stats' && !r.method));
    assert.deepEqual(c.calls, { user: 1, tick: 1, tab: 1, expired: 0 });
    assertSessionPreserved(c);
});

for (const value of [null, '', '0', '61', '-1', '1.5', ' 1', '1 ', '1e0', '٠١', '001', 'Fri, 06 Nov 2026 10:00:00 GMT']) {
    test(`invalid Retry-After ${JSON.stringify(value)} requires explicit retry`, async () => {
        const c = controller([response(429, value)]); await c.start();
        assertSessionPreserved(c);
        assert.equal(c.timers.size, 0);
        assert.equal(c.requests.length, 1);
        assert.equal(c.retry.hidden, false);
        assert.equal(c.retry.style.display, '');
        assert.equal(typeof c.retry.onclick, 'function');
        assert.match(c.text.textContent, /try again/i);
    });
}

test('a repeated 429 stops automatic retry and exposes manual recovery', async () => {
    const c = controller([response(429, '1'), response(429, '1')]);
    await c.start(); await c.fireTimer();
    assert.equal(c.requests.length, 2);
    assert.equal(c.timers.size, 0);
    assert.equal(c.retry.hidden, false);
    assertSessionPreserved(c);
});

for (const failure of [response(500), response(503, '1'), new Error('Network unavailable')]) {
    test(`transient ${failure.status || 'network'} error preserves session and manual retry succeeds`, async () => {
        const c = controller([failure, response()]); await c.start();
        assertSessionPreserved(c);
        assert.equal(c.retry.hidden, false);
        assert.equal(c.timers.size, 0);
        assert.match(c.text.textContent, /try again/i);
        assert.equal(typeof c.retry.onclick, 'function');
        c.retry.onclick(); await settle();
        assert.equal(c.requests.length, 2);
        assert.equal(c.retry.hidden, true);
        assert.equal(c.panel.authenticated, true);
        assert.deepEqual(c.calls, { user: 1, tick: 1, tab: 1, expired: 0 });
    });
}

test('concurrent bootstrap attempts share one in-flight request and initialization', async () => {
    let resolve;
    const pending = new Promise(done => { resolve = done; });
    const c = controller([pending]);
    c.panel._tryAuth(); c.panel._tryAuth();
    assert.equal(c.requests.length, 1);
    resolve(response()); await settle();
    assert.deepEqual(c.calls, { user: 1, tick: 1, tab: 1, expired: 0 });
});

test('429 metadata never automatically replays an API mutation', async () => {
    const c = controller([response(429, '1')]);
    await assert.rejects(c.panel.apiFetch('/api/admin/keys', { method: 'POST', body: { name: 'synthetic' } }), error => error.status === 429 && error.retryAfter === 1);
    assert.equal(c.requests.length, 1);
    assert.equal(c.requests[0].method, 'POST');
    assert.equal(c.timers.size, 0);
    assertSessionPreserved(c);
});
