/* Execute the shipped guard, rather than reimplementing its token logic. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const sourcePath = path.join(__dirname, '../../../src/sigrift/bridge/static/auth_guard.js');
const source = fs.readFileSync(sourcePath, 'utf8');

function browser({ cookie = '', session = '', key = '', storageFails = false } = {}) {
    const redirects = [];
    const requests = [];
    const context = {
        document: { cookie },
        sessionStorage: {
            getItem(name) {
                if (storageFails) throw new Error('Storage unavailable');
                return name === 'bridge_session_token' ? session : key;
            },
        },
        window: {
            location: { pathname: '/dashboard', replace: url => redirects.push(url) },
            fetch(url, options) { requests.push({ url, options, receiver: this }); return 'sent'; },
        },
        Headers,
    };
    vm.runInNewContext(source, context, { filename: sourcePath });
    return { context, redirects, requests };
}

test('cookie-only, session and API-key credentials each keep navigation authenticated', () => {
    for (const credentials of [
        { cookie: 'session_token=private; csrf_token=fixture-csrf' },
        { session: 'fixture-session' },
        { key: 'fixture-api-key' },
    ]) {
        const page = browser(credentials);
        assert.equal(page.redirects.length, 0);
        assert.equal(page.context.window.__bridge_auth.sessionToken, credentials.session || '');
        assert.equal(page.context.window.__bridge_auth.csrfToken, credentials.cookie ? 'fixture-csrf' : '');
    }
});

test('missing, malformed and inaccessible credentials require real login', () => {
    for (const credentials of [{}, { session: 'undefined' }, { session: 'null' }, { storageFails: true }]) {
        const page = browser(credentials);
        assert.deepEqual(page.redirects, ['/login?next=%2Fdashboard']);
        assert.equal(page.context.window.__bridge_auth.sessionToken, '');
    }
});

test('every mutating method receives the current CSRF cookie and preserves the fetch call', () => {
    for (const method of ['POST', 'put', 'DELETE', 'PATCH']) {
        const page = browser({ cookie: 'csrf_token=first', session: 'fixture-session' });
        page.context.document.cookie = 'other=value; csrf_token=current';
        const options = { method, headers: { Accept: 'application/json' } };
        const result = page.context.window.fetch('/api/write', options);
        assert.equal(result, 'sent');
        assert.equal(page.requests[0].options, options);
        assert.equal(options.headers['X-CSRF-Token'], 'current');
        assert.equal(options.headers.Accept, 'application/json');
        assert.equal(page.requests[0].receiver, page.context.window);
    }
});

test('read-only and cookie-free requests do not invent CSRF credentials', () => {
    const page = browser({ cookie: 'csrf_token=fixture-csrf' });
    page.context.window.fetch('/api/read');
    page.context.window.fetch('/api/read', { method: 'GET' });
    assert.equal(page.requests[0].options.headers, undefined);
    assert.equal(page.requests[1].options.headers, undefined);
    const noCookie = browser({ session: 'fixture-session' });
    noCookie.context.window.fetch('/api/write', { method: 'POST' });
    assert.equal(noCookie.requests[0].options.headers, undefined);
});

test('plain and Headers objects retain an explicitly supplied CSRF value', () => {
    const page = browser({ cookie: 'csrf_token=fixture-csrf' });
    const plain = { 'X-CSRF-Token': 'explicit' };
    page.context.window.fetch('/api/write', { method: 'POST', headers: plain });
    assert.equal(plain['X-CSRF-Token'], 'explicit');
    const headers = new Headers({ 'X-CSRF-Token': 'explicit' });
    page.context.window.fetch('/api/write', { method: 'POST', headers });
    assert.equal(headers.get('X-CSRF-Token'), 'explicit');
    const absent = new Headers();
    page.context.window.fetch('/api/write', { method: 'POST', headers: absent });
    assert.equal(absent.get('X-CSRF-Token'), 'fixture-csrf');
    const noHeaders = { method: 'POST' };
    page.context.window.fetch('/api/write', noHeaders);
    assert.equal(noHeaders.headers['X-CSRF-Token'], 'fixture-csrf');
});
