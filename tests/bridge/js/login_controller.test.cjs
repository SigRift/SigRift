/* Exercise the shipped login controller without third-party JS dependencies. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const sourcePath = path.join(__dirname, '../../../src/sigrift/bridge/static/login.js');
const source = fs.readFileSync(sourcePath, 'utf8');
const settle = () => new Promise(resolve => setImmediate(resolve));
const reply = (body, status = 200) => ({
    ok: status >= 200 && status < 300,
    status,
    headers: { get: () => null },
    json: async () => body,
});

function browser(responses, options = {}) {
    const elements = new Map();
    const storage = new Map(Object.entries(options.storage || {}));
    const requests = [];
    const redirects = [];
    const document = { cookie: options.cookie || '', activeElement: null };
    function node() {
        const classes = new Set();
        return {
            value: '', textContent: '', style: {}, disabled: false, children: [],
            classList: {
                add(name) { classes.add(name); },
                remove(name) { classes.delete(name); },
                contains(name) { return classes.has(name); },
                toggle(name, force) {
                    const on = force === undefined ? !classes.has(name) : force;
                    if (on) classes.add(name); else classes.delete(name);
                },
            },
            handlers: {},
            addEventListener(type, handler) { (this.handlers[type] ||= []).push(handler); },
            removeEventListener(type, handler) {
                this.handlers[type] = (this.handlers[type] || []).filter(value => value !== handler);
            },
            appendChild(child) {
                this.children.push(child);
                child.parentNode = this;
                function register(value) {
                    if (value.id) elements.set(value.id, value);
                    value.children.forEach(register);
                }
                register(child);
            },
            remove() {
                if (this.parentNode) {
                    this.parentNode.children = this.parentNode.children.filter(value => value !== this);
                    this.parentNode = null;
                }
                function unregister(value) {
                    if (elements.get(value.id) === value) elements.delete(value.id);
                    value.children.forEach(unregister);
                }
                unregister(this);
            },
            focus() { document.activeElement = this; },
        };
    }
    function element(id) {
        if (!elements.has(id)) elements.set(id, node());
        return elements.get(id);
    }
    const tabs = ['login', 'apikey'].map(name => {
        const tab = element('tab-' + name);
        tab.getAttribute = () => name;
        return tab;
    });
    Object.assign(document, {
        getElementById: id => id.startsWith('pwchange-') ? elements.get(id) || null : element(id),
        createElement: node,
        querySelectorAll: () => tabs,
        addEventListener: (_type, handler) => handler(),
    });
    const context = {
        document,
        window: { location: { origin: 'https://bridge.example', search: options.search || '', replace: url => redirects.push(url) } },
        sessionStorage: {
            setItem: (key, value) => storage.set(key, value),
            removeItem: key => storage.delete(key),
        },
        fetch: async (url, options) => {
            requests.push({ url, ...options, body: JSON.parse(options.body) });
            assert.ok(responses.length, 'unexpected request');
            return await responses.shift();
        },
        URLSearchParams, URL,
    };
    // A real source filename lets Node's V8 report include the shipped code.
    vm.runInNewContext(source, context, { filename: sourcePath });
    element('username').value = 'fixture-user';
    element('password').value = 'fixture-password';
    return {
        element, storage, requests, redirects, document, sessionStorage: context.sessionStorage,
        async event(id, type, data = {}) {
            for (const handler of element(id).handlers[type] || []) handler(data);
            await settle();
        },
        async click(id) { await this.event(id, 'click'); },
    };
}

const challenge = token => reply({
    mfa_required: true, mfa_token: token, session_token: '',
});

for (const code of ['123456', 'ABCD1234']) {
    test(`MFA login sends the API contract for ${code.length}-character codes`, async () => {
        const page = browser([
            challenge('fixture-challenge'), reply({ session_token: 'fixture-session' }),
        ]);
        await page.click('login-submit');
        assert.equal(page.element('mfa-section').style.display, 'block');
        assert.equal(page.storage.size, 0, 'challenge must not become a session');
        page.element('mfa-code').value = code;
        await page.click('mfa-submit');

        assert.equal(page.requests[1].url, '/api/auth/mfa/verify');
        assert.deepEqual(page.requests[1].body, {
            mfa_token: 'fixture-challenge', totp_code: code,
        });
        assert.equal(page.requests[1].headers.Authorization, undefined);
        assert.equal(page.requests[1].credentials, 'same-origin');
        assert.equal(page.storage.get('bridge_session_token'), 'fixture-session');
        assert.deepEqual(page.redirects, ['/dashboard']);
    });
}

test('a failed code returns to password login for a fresh single-use challenge', async () => {
    const page = browser([
        challenge('first-challenge'), reply({ detail: 'Invalid MFA code' }, 401),
        challenge('second-challenge'), reply({ session_token: 'fixture-session' }),
    ]);
    await page.click('login-submit');
    page.element('mfa-code').value = '000000';
    await page.click('mfa-submit');
    assert.equal(page.storage.size, 0);
    assert.equal(page.redirects.length, 0);
    assert.equal(page.element('mfa-section').style.display, 'none');
    assert.equal(page.element('login-submit').style.display, '');
    assert.match(page.element('login-error').textContent, /sign in again/i);

    await page.click('login-submit');
    page.element('mfa-code').value = '123456';
    await page.click('mfa-submit');
    assert.equal(page.requests[1].body.mfa_token, 'first-challenge');
    assert.equal(page.requests[3].body.mfa_token, 'second-challenge');
    assert.deepEqual(page.redirects, ['/dashboard']);
});

test('a second click cannot consume the same challenge while verification is pending', async () => {
    let finish;
    const pending = new Promise(resolve => { finish = resolve; });
    const page = browser([challenge('fixture-challenge'), pending]);
    await page.click('login-submit');
    page.element('mfa-code').value = '123456';
    await page.click('mfa-submit');
    await page.click('mfa-submit');
    assert.equal(page.requests.length, 2);
    finish(reply({ session_token: 'fixture-session' }));
    await settle();
    assert.deepEqual(page.redirects, ['/dashboard']);
});

test('a malformed challenge response cannot open the MFA step', async () => {
    const page = browser([reply({ mfa_required: true, session_token: '' })]);
    await page.click('login-submit');
    assert.notEqual(page.element('mfa-section').style.display, 'block');
    assert.match(page.element('login-error').textContent, /challenge/i);
    assert.equal(page.storage.size, 0);
    assert.equal(page.redirects.length, 0);
});

test('an empty code does not send a verification request', async () => {
    const page = browser([challenge('fixture-challenge')]);
    await page.click('login-submit');
    await page.click('mfa-submit');
    assert.equal(page.requests.length, 1);
    assert.match(page.element('login-error').textContent, /enter mfa code/i);
});

test('MFA submission without a live challenge returns to password login', async () => {
    const page = browser([]);
    page.element('mfa-code').value = '123456';
    await page.click('mfa-submit');
    assert.equal(page.requests.length, 0);
    assert.equal(page.element('mfa-section').style.display, 'none');
    assert.equal(page.element('login-submit').style.display, '');
    assert.match(page.element('login-error').textContent, /challenge missing/i);
    assert.equal(page.storage.size, 0);
});

test('a non-JSON MFA server failure resets the challenge and allows retry', async () => {
    const page = browser([
        challenge('fixture-challenge'),
        { ok: false, json: async () => { throw new Error('not JSON'); } },
    ]);
    await page.click('login-submit');
    page.element('mfa-code').value = '123456';
    await page.click('mfa-submit');
    assert.equal(page.element('mfa-section').style.display, 'none');
    assert.equal(page.element('mfa-submit').disabled, false);
    assert.match(page.element('login-error').textContent, /MFA verification failed.*sign in again/i);
    assert.equal(page.storage.size, 0);
    assert.equal(page.redirects.length, 0);
});

test('password-only login still reaches the dashboard', async () => {
    const page = browser([reply({ session_token: 'fixture-session' })]);
    await page.click('login-submit');
    assert.equal(page.requests.length, 1);
    assert.equal(page.storage.get('bridge_session_token'), 'fixture-session');
    assert.deepEqual(page.redirects, ['/dashboard']);
});

test('normalized double-slash paths retain the verified application origin', async () => {
    for (const next of ['/.//evil.example', '/a/..//evil.example', '/%2e//evil.example']) {
        const page = browser([reply({})], { search: '?next=' + encodeURIComponent(next) });
        await page.click('login-submit');
        assert.deepEqual(page.redirects, ['https://bridge.example//evil.example']);
        assert.equal(new URL(page.redirects[0], 'https://bridge.example').origin, 'https://bridge.example');
    }
});

test('redirects stay on the application origin, including browser-normalized paths', async () => {
    for (const next of ['https://evil.example', '//evil.example', '/\\evil.example', '/\t/evil.example', '/\n/evil.example', '/\\[::1']) {
        const page = browser([reply({})], { search: '?next=' + encodeURIComponent(next) });
        await page.click('login-submit');
        assert.equal(new URL(page.redirects[0], 'https://bridge.example').origin, 'https://bridge.example', next);
        assert.deepEqual(page.redirects, ['/dashboard']);
    }
    const page = browser([reply({})], { search: '?next=' + encodeURIComponent('/dashboard?tab=wifi#details') });
    await page.click('login-submit');
    assert.deepEqual(page.redirects, ['https://bridge.example/dashboard?tab=wifi#details']);
});

test('empty login fields fail locally and stale credentials are cleared', async () => {
    const page = browser([], { storage: { bridge_session_token: 'old', bridge_api_key: 'old', bridge_admin_key: 'old' } });
    assert.equal(page.storage.size, 0);
    for (const field of ['username', 'password']) {
        const previous = page.element(field).value;
        page.element(field).value = '';
        await page.click('login-submit');
        assert.match(page.element('login-error').textContent, /username and password/);
        page.element(field).value = previous;
    }
    assert.equal(page.requests.length, 0);
});

test('rate-limit messages respect the server cooldown and recover the submit button', async () => {
    for (const [retry, expected] of [['1', '1 second'], ['2', '2 seconds'], ['60', '1 minute'], ['61', '2 minutes'], ['0', 'please wait'], ['invalid', 'please wait']]) {
        const response = reply({}, 429);
        response.headers.get = () => retry;
        const page = browser([response]);
        await page.click('login-submit');
        assert.ok(page.element('login-error').textContent.includes(expected));
        assert.equal(page.element('login-submit').disabled, false);
        assert.equal(page.element('login-submit').textContent, 'Sign In');
        assert.equal(page.storage.size, 0);
    }
    for (const [response, expected] of [
        [{ then(_resolve, reject) { reject(null); } }, 'Login failed'],
        [reply({ detail: 'Account locked' }, 429), 'Account locked'],
        [reply({ detail: 'Incorrect credentials' }, 401), 'Incorrect credentials'],
        [reply(null, 401), 'Login failed'],
        [{ ...reply({}, 500), json: async () => { throw new Error('invalid JSON'); } }, 'Login failed'],
    ]) {
        const page = browser([response]);
        await page.click('login-submit');
        assert.equal(page.element('login-error').textContent, expected);
        assert.equal(page.redirects.length, 0);
    }
});

test('API-key tab clears a pending MFA challenge and accepts only a nonempty key', async () => {
    const page = browser([challenge('fixture-challenge')]);
    await page.click('login-submit');
    await page.click('tab-apikey');
    assert.equal(page.element('mfa-section').style.display, 'none');
    assert.equal(page.element('panel-apikey').classList.contains('active'), true);
    await page.click('login-submit');
    assert.equal(page.element('login-error').textContent, 'Enter an API key');
    page.element('apikey').value = '  fixture-key  ';
    await page.event('apikey', 'keydown', { key: 'x' });
    assert.equal(page.redirects.length, 0);
    await page.event('apikey', 'keydown', { key: 'Enter' });
    assert.equal(page.storage.get('bridge_api_key'), 'fixture-key');
    assert.equal(page.storage.has('bridge_session_token'), false);
    assert.deepEqual(page.redirects, ['/dashboard']);
    await page.click('tab-login');
    assert.equal(page.element('panel-login').classList.contains('active'), true);
});

test('forced password change validates input and sends authenticated CSRF-protected updates', async () => {
    for (const token of ['fixture-session', '']) {
        const page = browser([
            reply({ password_change_required: true, session_token: token }),
            reply({ session_token: 'replacement-session' }),
        ], { cookie: token ? 'other=1; csrf_token=fixture-csrf' : '' });
        await page.event('username', 'keydown', { key: 'Enter' });
        assert.equal(page.redirects.length, 0);
        assert.equal(page.element('pwchange-section').children.length, 4);
        page.element('pwchange-new').value = 'short';
        await page.click('pwchange-submit');
        assert.match(page.element('login-error').textContent, /at least 8/);
        page.element('pwchange-new').value = 'replacement-password';
        page.element('pwchange-confirm').value = 'different-password';
        await page.click('pwchange-submit');
        assert.match(page.element('login-error').textContent, /do not match/);
        assert.equal(page.requests.length, 1);
        page.element('pwchange-confirm').value = 'replacement-password';
        await page.event('pwchange-confirm', 'keydown', { key: 'x' });
        assert.equal(page.requests.length, 1);
        await page.event('pwchange-confirm', 'keydown', { key: 'Enter' });
        const request = page.requests[1];
        assert.equal(request.url, '/api/auth/change-password');
        assert.deepEqual(request.body, { current_password: 'fixture-password', new_password: 'replacement-password' });
        assert.equal(request.headers.Authorization, token ? 'Bearer fixture-session' : undefined);
        assert.equal(request.headers['X-CSRF-Token'], token ? 'fixture-csrf' : undefined);
        assert.equal(request.credentials, 'same-origin');
        assert.equal(page.storage.get('bridge_session_token'), 'replacement-session');
        assert.deepEqual(page.redirects, ['/dashboard']);
    }
});

test('failed password changes preserve the restricted session and allow retry', async () => {
    const page = browser([
        reply({ password_change_required: true, session_token: 'limited-session' }),
        reply({ detail: 'Password policy rejected' }, 400),
        { ...reply({}, 500), json: async () => { throw new Error('invalid JSON'); } },
        reply(null, 400),
        reply({}),
    ]);
    await page.click('login-submit');
    page.element('pwchange-new').value = 'replacement-password';
    page.element('pwchange-confirm').value = 'replacement-password';
    for (const expected of ['Password policy rejected', 'Password change failed', 'Password change failed']) {
        await page.click('pwchange-submit');
        assert.equal(page.element('login-error').textContent, expected);
        assert.equal(page.storage.get('bridge_session_token'), 'limited-session');
        assert.equal(page.redirects.length, 0);
    }
    await page.click('pwchange-submit');
    assert.deepEqual(page.redirects, ['/dashboard']);
});

test('keyboard submission coexists with the Caps Lock indicator', async () => {
    const page = browser([challenge('fixture-challenge'), reply({})]);
    for (const id of ['username', 'password', 'mfa-code']) {
        await page.event(id, 'keydown', { key: 'x' });
    }
    assert.equal(page.requests.length, 0);
    page.element('password').focus();
    await page.event('password', 'keyup', { getModifierState: () => true });
    assert.equal(page.element('caps-lock-warning').classList.contains('visible'), true);
    await page.event('password', 'keyup', { getModifierState: () => false });
    assert.equal(page.element('caps-lock-warning').classList.contains('visible'), false);
    page.element('username').focus();
    await page.event('password', 'keyup', { getModifierState: () => true });
    assert.equal(page.element('caps-lock-warning').classList.contains('visible'), false);
    await page.event('password', 'blur');
    await page.event('password', 'keydown', { key: 'Enter' });
    page.element('mfa-code').value = '123456';
    await page.event('mfa-code', 'keydown', { key: 'Enter' });
    assert.deepEqual(page.redirects, ['/dashboard']);
});


test('a committed password change without a replacement session returns to clean sign-in', async () => {
    let finish;
    const pending = new Promise(resolve => { finish = resolve; });
    const page = browser([
        reply({ password_change_required: true, session_token: 'revoked-session' }),
        pending,
        reply({ session_token: 'fresh-session' }),
    ]);
    await page.click('login-submit');
    const oldButton = page.element('pwchange-submit');
    const oldConfirm = page.element('pwchange-confirm');
    const oldNew = page.element('pwchange-new');
    const queuedSubmit = oldButton.handlers.click[0];
    oldNew.value = oldConfirm.value = 'replacement-password';
    page.element('apikey').value = 'stale-key';
    page.storage.set('bridge_api_key', 'stale-key');
    page.storage.set('bridge_admin_key', 'stale-admin-key');
    await page.click('pwchange-submit');
    // Tab changes remain possible while the actual HTTP response is pending.
    await page.click('tab-apikey');
    finish(reply({ status: 'password_changed', reauthentication_required: true }));
    await settle();
    assert.deepEqual(page.redirects, []);
    assert.equal(page.storage.size, 0);
    for (const input of [oldNew, oldConfirm, page.element('password'), page.element('apikey')]) {
        assert.equal(input.value, '', 'old and new credentials must not remain in inputs');
    }
    assert.equal(page.document.getElementById('pwchange-section'), null);
    assert.equal(oldButton.handlers.click.length, 0);
    assert.equal(oldConfirm.handlers.keydown.length, 0);
    assert.equal(page.element('panel-login').classList.contains('active'), true);
    assert.equal(page.element('panel-apikey').classList.contains('active'), false);
    assert.equal(page.element('tab-login').classList.contains('active'), true);
    assert.equal(page.element('tab-apikey').classList.contains('active'), false);
    assert.equal(page.element('login-submit').style.display, '');
    assert.equal(page.element('login-submit').disabled, false);
    assert.equal(page.document.activeElement, page.element('password'));
    assert.equal(page.element('login-error').textContent, 'Password changed. Sign in with your new password.');
    queuedSubmit();
    await settle();
    assert.equal(page.requests.length, 2, 'a stale password-change action must not replay the old password');
    await page.click('login-submit');
    assert.equal(page.requests.length, 2, 'sign-in requires the user to enter the new password');
    page.element('password').value = 'replacement-password';
    await page.click('login-submit');
    assert.equal(page.requests[2].url, '/api/auth/login');
    assert.equal(page.requests[2].body.password, 'replacement-password');
    assert.equal(page.requests[2].headers.Authorization, undefined);
    assert.equal(page.storage.get('bridge_session_token'), 'fresh-session');
    assert.deepEqual(page.redirects, ['/dashboard']);
});

test('only a boolean reauthentication flag changes the successful password-change flow', async () => {
    for (const flag of [undefined, false, 'true', 1]) {
        const page = browser([
            reply({ password_change_required: true, session_token: 'limited-session' }),
            reply({ session_token: 'replacement-session', reauthentication_required: flag }),
        ]);
        await page.click('login-submit');
        page.element('pwchange-new').value = page.element('pwchange-confirm').value = 'replacement-password';
        await page.click('pwchange-submit');
        assert.equal(page.storage.get('bridge_session_token'), 'replacement-session');
        assert.deepEqual(page.redirects, ['/dashboard']);
    }
});

test('a new restricted login cannot reuse the old password-change listeners or credentials', async () => {
    const page = browser([
        reply({ password_change_required: true, session_token: 'first-limited' }),
        reply({ status: 'password_changed', reauthentication_required: true }),
        reply({ password_change_required: true, session_token: 'second-limited' }),
        reply({ session_token: 'replacement-session' }),
    ]);
    await page.click('login-submit');
    const oldButton = page.element('pwchange-submit');
    page.element('pwchange-new').value = page.element('pwchange-confirm').value = 'first-new-password';
    await page.click('pwchange-submit');
    page.element('password').value = 'second-current-password';
    await page.click('login-submit');
    assert.notEqual(page.element('pwchange-submit'), oldButton);
    page.element('pwchange-new').value = page.element('pwchange-confirm').value = 'second-new-password';
    for (const handler of oldButton.handlers.click) handler();
    await settle();
    assert.equal(page.requests.length, 3);
    await page.event('pwchange-confirm', 'keydown', { key: 'Enter' });
    assert.equal(page.requests[3].headers.Authorization, 'Bearer second-limited');
    assert.deepEqual(page.requests[3].body, {
        current_password: 'second-current-password', new_password: 'second-new-password',
    });
    assert.deepEqual(page.redirects, ['/dashboard']);
});


test('committed password-change cleanup survives unavailable session storage', async () => {
    const page = browser([
        reply({ password_change_required: true, session_token: 'limited-session' }),
        reply({ status: 'password_changed', reauthentication_required: true }),
    ]);
    await page.click('login-submit');
    const oldButton = page.element('pwchange-submit');
    const oldNew = page.element('pwchange-new');
    const oldConfirm = page.element('pwchange-confirm');
    oldNew.value = oldConfirm.value = 'replacement-password';
    page.element('apikey').value = 'fixture-key';
    const attempted = [];
    page.sessionStorage.removeItem = key => { attempted.push(key); throw new Error('Storage unavailable'); };
    await page.click('pwchange-submit');
    assert.equal(page.element('login-error').textContent, 'Password changed. Sign in with your new password.');
    assert.deepEqual(attempted.sort(), ['bridge_admin_key', 'bridge_api_key', 'bridge_session_token']);
    for (const input of [oldNew, oldConfirm, page.element('password'), page.element('apikey')]) assert.equal(input.value, '');
    assert.equal(page.document.getElementById('pwchange-section'), null);
    assert.equal(oldButton.handlers.click.length, 0);
    assert.equal(oldConfirm.handlers.keydown.length, 0);
    assert.equal(page.element('login-submit').style.display, '');
    assert.equal(page.element('login-submit').disabled, false);
    assert.equal(page.document.activeElement, page.element('password'));
    assert.deepEqual(page.redirects, []);
    assert.equal(page.requests.length, 2);
});

test('password-change click and Enter cannot submit concurrently, but failure permits retry', async () => {
    let finish;
    const pending = new Promise(resolve => { finish = resolve; });
    const page = browser([
        reply({ password_change_required: true, session_token: 'limited-session' }),
        pending,
        reply({ status: 'password_changed', reauthentication_required: true }),
    ]);
    await page.click('login-submit');
    page.element('pwchange-new').value = page.element('pwchange-confirm').value = 'replacement-password';
    await page.click('pwchange-submit');
    await page.click('pwchange-submit');
    await page.event('pwchange-confirm', 'keydown', { key: 'Enter' });
    assert.equal(page.requests.length, 2, 'only one password mutation may be in flight');
    assert.equal(page.element('pwchange-submit').disabled, true);
    finish(reply({ detail: 'Password was not changed' }, 503));
    await settle();
    assert.equal(page.element('login-error').textContent, 'Password was not changed');
    assert.equal(page.element('pwchange-submit').disabled, false);
    assert.equal(page.storage.get('bridge_session_token'), 'limited-session');
    await page.event('pwchange-confirm', 'keydown', { key: 'Enter' });
    assert.equal(page.requests.length, 3);
    assert.deepEqual(page.requests[2].body, { current_password: 'fixture-password', new_password: 'replacement-password' });
    assert.equal(page.element('login-error').textContent, 'Password changed. Sign in with your new password.');
    assert.deepEqual(page.redirects, []);
});
