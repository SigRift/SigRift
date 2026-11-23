/* Exercise the shipped startup controller, including actual Promise chains. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const sourcePath = path.join(__dirname, '../../../src/sigrift/bridge/static/startup.js');
const source = fs.readFileSync(sourcePath, 'utf8');
const settle = () => new Promise(resolve => setImmediate(resolve));
const reply = (body, status = 200) => ({ ok: status >= 200 && status < 300, json: async () => body });

async function browser(responses) {
    const nodes = new Map();
    const timers = [];
    const requests = [];
    const location = { href: '/static/startup.html' };
    const element = id => {
        if (!nodes.has(id)) nodes.set(id, { textContent: '', innerHTML: '', className: '', style: {} });
        return nodes.get(id);
    };
    vm.runInNewContext(source, {
        document: { getElementById: element },
        window: { location },
        setTimeout: (fn, delay) => { timers.push({ fn, delay }); },
        fetch: async url => {
            requests.push(url);
            assert.ok(responses.length, 'unexpected status request');
            const response = responses.shift();
            if (response instanceof Error) throw response;
            return response;
        },
    }, { filename: sourcePath });
    await settle();
    return {
        element, timers, requests, location,
        async tick(delay) {
            assert.equal(timers[0]?.delay, delay);
            timers.shift().fn();
            await settle();
        },
    };
}

for (const state of ['pending', 'not_started']) {
    test(`${state} status remains indeterminate and polls until success`, async () => {
        const page = await browser([reply({ state }), reply({ state: 'passed', db_size_mb: 1000, elapsed_s: 8 })]);
        assert.match(page.element('progress-fill').className, /indeterminate/);
        assert.match(page.element('message').innerHTML, /Waiting for database initialization/);
        assert.equal(page.element('db-size').textContent, '0');
        assert.equal(page.element('elapsed').textContent, '0s');
        await page.tick(1000);
        assert.equal(page.element('progress-fill').style.width, '100%');
        assert.match(page.element('message').textContent, /passed/);
        assert.equal(page.location.href, '/static/startup.html');
        await page.tick(2000);
        assert.equal(page.location.href, '/dashboard');
        assert.equal(page.timers.length, 0);
        assert.deepEqual(page.requests, ['/api/integrity-status', '/api/integrity-status']);
    });
}

test('running estimate advances, caps at95 and never becomes negative', async () => {
    const page = await browser([reply({ state: 'running', db_size_mb: 1000, elapsed_s: 15 }), reply({ state: 'running', db_size_mb: 1000, elapsed_s: 45 })]);
    assert.equal(page.element('progress-fill').style.width, '50%');
    assert.equal(page.element('est-remaining').textContent, '15s');
    assert.match(page.element('message').innerHTML, /1000 MB/);
    await page.tick(1000);
    assert.equal(page.element('progress-fill').style.width, '95%');
    assert.equal(page.element('est-remaining').textContent, '0s');
});

test('zero-sized running database has an indeterminate estimate', async () => {
    const page = await browser([reply({ state: 'running', db_size_mb: 0, elapsed_s: 0 })]);
    assert.match(page.element('progress-fill').className, /indeterminate/);
    assert.equal(page.element('est-remaining').textContent, '--');
    assert.notEqual(page.element('progress-fill').style.width, 'NaN%');
    assert.equal(page.timers[0].delay, 1000);
});

test('skipped check redirects once after one second', async () => {
    const page = await browser([reply({ state: 'skipped' })]);
    assert.equal(page.element('state-badge').textContent, 'Skipped');
    assert.equal(page.element('progress-fill').style.width, '100%');
    assert.match(page.element('message').textContent, /skipped/);
    await page.tick(1000);
    assert.equal(page.location.href, '/dashboard');
    assert.equal(page.timers.length, 0);
});

for (const [state, error] of [['failed', '<img src=x onerror=alert(1)>'], ['error', '']]) {
    test(`${state} stays visible as text without redirecting or retrying`, async () => {
        const page = await browser([reply({ state, error })]);
        assert.equal(page.element('message').textContent, 'Check failed: ' + (error || 'unknown error'));
        assert.equal(page.element('message').innerHTML, '');
        assert.equal(page.element('progress-fill').style.background, '#ef4444');
        assert.equal(page.timers.length, 0);
        assert.equal(page.location.href, '/static/startup.html');
    });
}

for (const [name, response] of [
    ['network failure', new Error('offline')],
    ['invalid JSON', { ok: true, json: async () => { throw new SyntaxError('invalid'); } }],
    ['HTTP503 with misleading success body', reply({ state: 'passed' }, 503)],
    ['null payload', reply(null)],
    ['missing state', reply({})],
    ['unknown state', reply({ state: 'unknown' })],
]) {
    test(`${name} retries without a false successful redirect`, async () => {
        const page = await browser([response, reply({ state: 'passed' })]);
        assert.equal(page.location.href, '/static/startup.html');
        assert.match(page.element('message').innerHTML, /Connecting/);
        await page.tick(2000);
        assert.match(page.element('message').textContent, /passed/);
        await page.tick(2000);
        assert.equal(page.location.href, '/dashboard');
        assert.equal(page.requests.length, 2);
        assert.equal(page.timers.length, 0);
    });
}
