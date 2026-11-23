/* Actual dashboard apiFetch: what a 401 writes to the browser console. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const test = require('node:test');
const root = path.resolve(__dirname, '../../..');
const file = path.join(root, 'src/sigrift/bridge/static/dashboard.js');

function dashboard({status}) {
    const logged = [];
    const record = level => (...args) => logged.push({level, text: args.map(String).join(' ')});
    const requests = [];
    const context = {
        console: {log: record('log'), info: record('info'), warn: record('warn'), error: record('error'), debug: record('debug')},
        document: {addEventListener() {}, getElementById: () => null, querySelectorAll: () => [], cookie: ''},
        window: {addEventListener() {}},
        sessionStorage: {getItem: () => null, setItem() {}, removeItem() {}},
        localStorage: {getItem: () => null, setItem() {}, removeItem() {}},
        setTimeout() {}, clearTimeout() {}, setInterval() {}, clearInterval() {},
        FormData: class FormData {},
        fetch: async (url, opts) => {
            requests.push({url, opts});
            return {status, ok: status < 400, headers: {get: () => 'application/json'}, json: async () => ({})};
        },
    };
    vm.runInNewContext(fs.readFileSync(file, 'utf8'), context, {filename: file});
    const db = Object.create(context.BridgeDashboard.prototype);
    return {db, logged, requests};
}

const TOKEN = 'sekrit-session-token-0123456789abcdef';

test('a 401 is logged with its path and no part of the session token', async () => {
    const {db, logged, requests} = dashboard({status: 401});
    db.sessionToken = TOKEN;
    db.apiKey = '';
    await assert.rejects(db.apiFetch('/api/status'), /Unauthorized/);
    assert.equal(requests.length, 1);
    assert.equal(logged.length, 1, JSON.stringify(logged));
    assert.equal(logged[0].level, 'warn');
    assert.match(logged[0].text, /^401 on \/api\/status\?_t=\d+$/);
    // Not the token, nor its prefix (the log showed the first 8 characters).
    assert.ok(!logged[0].text.includes(TOKEN.slice(0, 4)), logged[0].text);
    assert.ok(!/token/i.test(logged[0].text), logged[0].text);
});

test('a 401 in cookie mode or with an API key logs the same line', async () => {
    for (const auth of [{sessionToken: '', apiKey: ''}, {sessionToken: '', apiKey: 'key-0123456789'}]) {
        const {db, logged} = dashboard({status: 401});
        Object.assign(db, auth);
        await assert.rejects(db.apiFetch('/api/nodes', {method: 'POST', body: {a: 1}}), /Unauthorized/);
        assert.deepEqual(logged.map(entry => entry.text), ['401 on /api/nodes']);
    }
});
