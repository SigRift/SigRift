/* The shipped admin console's security behaviour, in the stub DOM of
 * admin_dom.cjs: markup the shipped code writes is parsed by a real HTML
 * parser (parse5) and serialised like a browser does, so escaping, attribute
 * values and injected elements are read as a browser would build them.
 * Requests go to a recording fake network that answers with real fetch
 * Response objects.
 */
const assert = require('node:assert/strict');
const test = require('node:test');
const {
    adminPage, noUnexpectedConsoleErrors, reply, settle, FakeEvent, credentialHeaders, READ_ONLY_CONTROLS, assertInert,
    MARKUP, ATTR_MARKUP, CSRF, assertCookieWrite, call, cell, escapeText, PAGE_SCRIPTS,
} = require('./admin_dom.cjs');

test.afterEach(noUnexpectedConsoleErrors);

const KEY = {
    key_id: 'key_a1', is_master: false, role: 'viewer', stored_role: 'viewer', description: 'ops laptop',
    node_id: 'edge-1', created_at: '2026-11-01T00:00:00Z', expires_at: null, effective_expires_at: null, expired: false,
};
const MASTER = { key_id: 'master', is_master: true, role: 'admin', description: 'bootstrap', created_at: '2026-01-01T00:00:00Z', expired: false };
const CERT = {
    identity: 'edge-1', role: 'node', serial: '0a1b2c3d4e5f60718293a4b5c6d7e8f9',
    issued_at: '2026-10-01T00:00:00Z', not_after: '2027-10-01T00:00:00Z', revoked: false,
};
const NODE = {
    node_id: 'edge_1', host: '10.0.0.5', status: 'active', cpu_percent: 12.5, memory_mb: 512,
    last_seen: '2026-11-10T11:59:00Z', capabilities: { cpu_temp: 50, uptime_seconds: 3600 },
};

/* ------------------------------------------------------------------ */
/* Request construction                                                */
/* ------------------------------------------------------------------ */

test('cookie session: reads carry no CSRF token and no header credentials', async () => {
    const page = await adminPage();
    const urls = page.requests.map(r => r.url);
    for (const url of ['/api/admin/stats', '/api/auth/me', '/api/admin/keys', '/api/ca/certs']) assert.ok(urls.includes(url), url + ' is loaded');
    for (const request of page.requests) {
        assert.equal(request.method, 'GET', request.url);
        assert.equal(request.credentials, 'same-origin', request.url);
        assert.deepEqual(credentialHeaders(request), {}, request.url);
    }
    assert.equal(page.byId('admin-status').querySelector('.status-text').textContent, 'Authenticated');
    assert.deepEqual(page.redirects, []);
});

for (const [name, storage, expected] of [
    ['an admin key wins over a viewer key and a session token', { bridge_admin_key: 'adm', bridge_api_key: 'api', bridge_session_token: 'tok' }, { 'X-API-Key': 'adm' }],
    ['a stored API key is sent alone', { bridge_api_key: 'api', bridge_session_token: 'tok' }, { 'X-API-Key': 'api' }],
    ['a session token is sent only without a key', { bridge_session_token: 'tok' }, { 'X-Session-Token': 'tok' }],
]) {
    test('stored credentials: ' + name + ' (admin and crypto requests alike)', async () => {
        const page = await adminPage({ cookie: '', storage });
        await page.tab('crypto');
        const crypto = page.requests.find(r => r.url === '/api/crypto/keys');
        assert.ok(crypto, 'opening the crypto tab lists crypto keys');
        for (const request of [page.requests[0], crypto]) {
            assert.deepEqual(credentialHeaders(request), expected, request.url);
            assert.equal(request.credentials, 'same-origin');
        }
        assert.deepEqual(page.redirects, []);
    });
}

test('a URL hash naming a tab opens it; a crafted one opens none and the console still works', async () => {
    const activeTab = page => page.doc.querySelector('[data-tab].active').getAttribute('data-tab');
    const opened = await adminPage({ hash: '#nodes', routes: nodesRoutes() });
    assert.equal(activeTab(opened), 'nodes');
    assert.ok(opened.requests.some(r => r.url === '/api/admin/nodes'), 'the tab loads once the console signs in');
    const plain = await adminPage({ routes: nodesRoutes() });
    // Built into a [data-tab="..."] selector, the first makes it throw (no
    // console at all), and the last selects the Nodes link by its href.
    for (const hash of ['#nodes"]', "#nodes'] , [data-tab", '#x"], a[href="#nodes']) {
        const page = await adminPage({ hash, routes: nodesRoutes() });
        assert.equal(activeTab(page), activeTab(plain), hash);
        assert.deepEqual(page.requests.map(r => r.url), plain.requests.map(r => r.url), hash);
        assert.equal(page.byId('admin-status').querySelector('.status-text').textContent, 'Authenticated', hash);
        await page.tab('nodes');
        assert.ok(page.requests.some(r => r.url === '/api/admin/nodes'), hash);
    }
});

test('an API key change is not sent a CSRF token when the browser has no CSRF cookie', async () => {
    const page = await adminPage({
        cookie: '', storage: { bridge_admin_key: 'adm' },
        routes: { 'GET /api/admin/keys': () => reply(200, [KEY]), 'DELETE /api/admin/keys/key_a1': () => reply(204) },
    });
    await page.click(page.byId('keys-tbody').querySelector('[data-revoke]'));
    await page.click(page.button('Revoke'));
    const [revoke] = page.writes();
    assert.deepEqual(call(revoke), ['DELETE', '/api/admin/keys/key_a1', undefined]);
    assert.deepEqual(credentialHeaders(revoke), { 'X-API-Key': 'adm' });
});

test('identifiers from the server are sent as one encoded path segment', async () => {
    const id = 'key/../nodes?x=1#y';
    const serial = 'ab/../../ca?all';
    const page = await adminPage({
        routes: {
            'GET /api/admin/keys': () => reply(200, [{ ...KEY, key_id: id }]),
            'GET /api/ca/certs': () => reply(200, [{ ...CERT, serial }]),
        },
    });
    await page.click(page.byId('keys-tbody').querySelector('[data-revoke]'));
    await page.click(page.button('Revoke'));
    await page.click(page.byId('certs-tbody').querySelector('[data-revoke-cert]'));
    await page.click(page.button('Revoke'));
    assert.deepEqual(page.writes().map(r => r.method + ' ' + r.url), [
        'DELETE /api/admin/keys/key%2F..%2Fnodes%3Fx%3D1%23y',
        'POST /api/ca/revoke/ab%2F..%2F..%2Fca%3Fall',
    ]);
});

test('a failure without a JSON explanation is reported by its HTTP status and does not sign the admin out', async () => {
    const page = await adminPage({
        storage: { bridge_session_token: 'tok' },
        routes: {
            'GET /api/admin/keys': () => reply(200, [{ ...KEY, node_id: null }]),
            'GET /api/ca/certs': () => reply(200, [CERT]),
            // A proxy's HTML page, an empty body, a structured detail, and no response at all.
            'DELETE /api/admin/keys/key_a1': () => reply(502, '<html><b>Bad gateway</b><img src=x onerror=alert(1)></html>'),
            'POST /api/admin/keys/key_a1/rotate': () => reply(500),
            ['POST /api/ca/revoke/' + CERT.serial]: () => reply(504, ''),
            'POST /api/ca/issue': () => reply(422, { detail: [{ loc: ['body', 'identity'], msg: MARKUP }] }),
            'POST /api/admin/keys': () => { throw new TypeError('Failed to fetch'); },
        },
    });
    await page.click(page.byId('keys-tbody').querySelector('[data-revoke]'));
    await page.click(page.button('Revoke'));
    await page.click(page.byId('keys-tbody').querySelector('[data-rotate]'));
    await page.click(page.button('Rotate Key'));
    await page.click(page.byId('certs-tbody').querySelector('[data-revoke-cert]'));
    await page.click(page.button('Revoke'));
    await page.input(page.byId('new-cert-identity'), 'edge-2');
    await page.click(page.byId('mint-cert-btn'));
    await page.click(page.byId('create-key-btn'));

    assert.deepEqual(page.toasts(), [
        { text: 'Failed to revoke key: HTTP 502', type: 'error', markup: 0 },
        { text: 'Key rotation failed: HTTP 500', type: 'error', markup: 0 },
        { text: 'Failed to revoke: HTTP 504', type: 'error', markup: 0 },
        { text: 'Mint failed: HTTP 422', type: 'error', markup: 0 },
        { text: 'Key creation failed: Failed to fetch', type: 'error', markup: 0 },
    ]);
    assert.equal(page.byId('key-rotate-result').textContent, 'Rotation failed: HTTP 500');
    assert.equal(page.writes().length, 5);
    assert.deepEqual(page.redirects, [], 'only a 401 or 403 ends the session');
    assert.deepEqual([...page.store.keys()], ['bridge_session_token']);
    assert.equal(page.byId('create-key-btn').disabled, false);
    assert.deepEqual(await page.opens('nodes'), ['GET /api/admin/nodes'], 'the console still loads admin data');
});

/* ------------------------------------------------------------------ */
/* Authentication failures and session state                           */
/* ------------------------------------------------------------------ */

for (const status of [401, 403]) {
    test('a ' + status + ' on an admin change clears credentials, locks the console and goes to login', async () => {
        const page = await adminPage({
            storage: { bridge_session_token: 'tok', bridge_api_key: 'api', bridge_admin_key: 'adm' },
            routes: {
                'GET /api/admin/keys': () => reply(200, [KEY]),
                'DELETE /api/admin/keys/key_a1': () => reply(status, { detail: 'session revoked' }),
            },
        });
        await page.click(page.byId('keys-tbody').querySelector('[data-revoke]'));
        await page.click(page.button('Revoke'));
        assert.equal(page.writes().length, 1);
        assert.deepEqual([...page.store.keys()], []);
        assert.deepEqual(page.redirects, ['/login?next=%2Fadmin']);
        assert.equal(page.byId('admin-session-expiry').textContent, 'Session expired — please log in again');
        assert.equal(page.byId('admin-session-info').style.display, '');
        const actions = page.doc.querySelectorAll('button').filter(b => !b.matches(READ_ONLY_CONTROLS));
        assert.ok(actions.length > 20);
        assert.deepEqual(actions.filter(b => !b.disabled).map(b => b.id || b.textContent), [], 'every admin action is disabled');
        assert.deepEqual(page.toasts().filter(t => t.type === 'success'), []);
        assert.deepEqual(await page.opens('nodes'), [], 'opening another tab loads nothing');
    });
}

test('a refused first admin request loads no admin data, even when a tab is opened', async () => {
    const page = await adminPage({ routes: { 'GET /api/admin/stats': () => reply(401, { detail: 'no' }) } });
    assert.deepEqual(page.requests.map(r => r.url), ['/api/admin/stats']);
    assert.deepEqual(page.redirects, ['/login?next=%2Fadmin']);
    assert.notEqual(page.byId('admin-status').querySelector('.status-text').textContent, 'Authenticated');
    assert.equal(page.byId('keys-tbody').innerHTML, '');
    assert.deepEqual(await page.opens('audit'), []);
    assert.deepEqual(await page.opens('keys'), []);
});

test('the signed-in user is shown as text, a short session warns, and an expired one locks the console', async () => {
    let checks = 0;
    const page = await adminPage({
        routes: {
            'GET /api/admin/stats': () => reply(200, {}, { 'X-Session-Expires-In': '240' }),
            'GET /api/auth/me': () => reply(200, { auth_type: 'session', username: MARKUP },
                { 'X-Session-Expires-In': checks++ ? '0' : '240' }),
        },
    });
    const user = page.byId('admin-session-user'), expiry = page.byId('admin-session-expiry');
    assert.equal(user.textContent, 'Logged in as ' + MARKUP);
    assert.equal(user.children.length, 0);
    assert.equal(expiry.textContent, '— expires in 4 min');
    assert.match(expiry.style.color, /yellow/, 'a short session is shown in the warning colour');
    assert.equal(page.byId('admin-session-info').style.display, '');
    assert.equal(page.byId('create-key-btn').disabled, false);

    // A minute idle: the console re-checks the session; the server now says it is over.
    await page.advance(60_000);
    assert.equal(page.requests.filter(r => r.url === '/api/auth/me').length, 2);
    assert.equal(expiry.textContent, 'Session expired — please log in again');
    assert.equal(page.byId('create-key-btn').disabled, true);
    assert.deepEqual(await page.opens('nodes'), [], 'an expired console loads nothing');
});

test('an API-key identity is shown as text without an expiry', async () => {
    const page = await adminPage({ routes: { 'GET /api/auth/me': () => reply(200, { auth_type: 'api_key', key_id: MARKUP }) } });
    assert.equal(page.byId('admin-session-user').textContent, 'API key ' + MARKUP);
    assert.equal(page.byId('admin-session-user').children.length, 0);
    assert.equal(page.byId('admin-session-expiry').textContent, '');
});

/* ------------------------------------------------------------------ */
/* API keys                                                            */
/* ------------------------------------------------------------------ */

test('key list: server strings render as text and ids round-trip through the action attributes', async () => {
    const hostile = { ...KEY, key_id: ATTR_MARKUP, description: MARKUP, node_id: ATTR_MARKUP + '-node' };
    const page = await adminPage({ routes: { 'GET /api/admin/keys': () => reply(200, [hostile, MASTER]) } });
    const tbody = page.byId('keys-tbody');
    assertInert(tbody, 'key list');
    const [row, master] = tbody.querySelectorAll('tr');
    assert.equal(cell(row, 'Key ID').textContent, ATTR_MARKUP);
    assert.equal(cell(row, 'Desc').textContent, MARKUP);
    assert.equal(cell(row, 'Node').textContent, ATTR_MARKUP + '-node');
    assert.equal(row.querySelector('[data-revoke]').getAttribute('data-revoke'), ATTR_MARKUP);
    assert.equal(row.querySelector('[data-rotate]').getAttribute('data-node'), ATTR_MARKUP + '-node');
    assert.equal(row.querySelector('[data-role-change]').value, 'viewer');
    assert.equal(cell(master, 'Role').textContent, 'MASTER');
    assert.equal(cell(master, 'Actions').textContent, '--', 'the master key cannot be revoked, rotated or re-roled here');
    assert.equal(page.byId('keys-empty').style.display, 'none');

    await page.click(row.querySelector('[data-revoke]'));
    assertInert(page.modal(), 'revoke dialog');
    assert.match(page.modal().textContent, /Revoke key <b onmouseover=alert\(3\)>id&amp;<\/b>\?/);
});

test('each key row shows the role the server stores, so the admin sees the privilege actually granted', async () => {
    const roles = ['sensor', 'node', 'viewer', 'analyst', 'admin'];
    const page = await adminPage({
        routes: {
            'GET /api/admin/keys': () => reply(200, [
                ...roles.map(role => ({ ...KEY, key_id: 'key_' + role, role })),
                { ...KEY, key_id: 'key_legacy', role: undefined },
            ]),
        },
    });
    const rows = page.byId('keys-tbody').querySelectorAll('tr');
    assert.deepEqual(rows.map(row => [cell(row, 'Key ID').textContent, cell(row, 'Role').textContent, row.querySelector('[data-role-change]').value]), [
        ['key_sensor', 'SENSOR', 'sensor'],
        ['key_node', 'NODE', 'node'],
        ['key_viewer', 'VIEWER', 'viewer'],
        ['key_analyst', 'ANALYST', 'analyst'],
        ['key_admin', 'ADMIN', 'admin'],
        ['key_legacy', 'VIEWER', 'viewer'],
    ]);
});

test('revoking a key needs explicit confirmation: Cancel, Escape and the backdrop send nothing', async () => {
    const page = await adminPage({
        routes: { 'GET /api/admin/keys': () => reply(200, [KEY]), 'DELETE /api/admin/keys/key_a1': () => reply(204) },
    });
    const revoke = () => page.click(page.byId('keys-tbody').querySelector('[data-revoke]'));
    await revoke();
    assert.equal(page.modal().querySelector('.destructive').textContent, 'Revoke');
    await page.click(page.button('Cancel'));
    await revoke();
    await page.key('Escape');
    assert.equal(page.modal(), null);
    await revoke();
    const backdrop = page.doc.querySelector('.admin-modal-backdrop');
    backdrop.dispatchEvent(new FakeEvent('mousedown', { target: backdrop }));
    await settle();
    assert.equal(page.modal(), null);
    assert.deepEqual(page.writes(), []);

    await revoke();
    await page.click(page.button('Revoke'));
    const writes = page.writes();
    assert.deepEqual(writes.map(call), [['DELETE', '/api/admin/keys/key_a1', undefined]]);
    assertCookieWrite(writes[0], { json: false });
    assert.deepEqual(page.toasts(), [{ text: 'Key key_a1 revoked', type: 'success', markup: 0 }]);
    assert.equal(page.requests.filter(r => r.url === '/api/admin/keys').length, 2, 'the list is reloaded');
});

test('a refused revocation shows the server reason as text', async () => {
    const page = await adminPage({
        routes: {
            'GET /api/admin/keys': () => reply(200, [KEY]),
            'DELETE /api/admin/keys/key_a1': () => reply(409, { detail: MARKUP }),
        },
    });
    await page.click(page.byId('keys-tbody').querySelector('[data-revoke]'));
    await page.click(page.button('Revoke'));
    assert.deepEqual(page.toasts(), [{ text: 'Failed to revoke key: ' + MARKUP, type: 'error', markup: 0 }]);
});

test('changing a key role sends the new role with the CSRF token', async () => {
    const page = await adminPage({
        routes: { 'GET /api/admin/keys': () => reply(200, [KEY]), 'PUT /api/admin/keys/key_a1/permissions': () => reply(200, {}) },
    });
    await page.change(page.byId('keys-tbody').querySelector('[data-role-change]'), 'analyst');
    const [write] = page.writes();
    assert.deepEqual(call(write), ['PUT', '/api/admin/keys/key_a1/permissions', { role: 'analyst' }]);
    assertCookieWrite(write);
});

test('a refused role change is reported and the list shows the role still in effect', async () => {
    const page = await adminPage({
        routes: {
            'GET /api/admin/keys': () => reply(200, [KEY]),
            'PUT /api/admin/keys/key_a1/permissions': () => reply(500, { detail: 'store unavailable' }),
        },
    });
    await page.change(page.byId('keys-tbody').querySelector('[data-role-change]'), 'admin');
    assert.equal(page.writes().length, 1);
    assert.deepEqual(page.toasts().filter(t => t.type === 'error').length, 1, 'the failure is reported');
    assert.equal(page.byId('keys-tbody').querySelector('[data-role-change]').value, 'viewer', 'the refused role is not shown as applied');
});

test('a failed key listing is reported, not shown as "No API keys"', async () => {
    const page = await adminPage({ routes: { 'GET /api/admin/keys': () => reply(503, { detail: 'key store unavailable' }) } });
    assert.equal(page.toasts().filter(t => t.type === 'error' && t.text.includes('key store unavailable')).length, 1);
    assert.equal(page.byId('keys-empty').style.display, 'none');
});

test('a refused role change shows the reason as text and restores the select even when the list cannot reload', async () => {
    let listing = () => reply(200, [KEY]);
    const page = await adminPage({
        routes: {
            'GET /api/admin/keys': () => listing(),
            'PUT /api/admin/keys/key_a1/permissions': () => reply(409, { detail: MARKUP }),
        },
    });
    listing = () => reply(500, 'not json');
    const select = page.byId('keys-tbody').querySelector('[data-role-change]');
    await page.change(select, 'admin');
    assert.deepEqual(page.toasts(), [
        { text: 'Role change for key_a1 failed: ' + MARKUP, type: 'error', markup: 0 },
        { text: 'Could not load API keys: HTTP 500', type: 'error', markup: 0 },
    ]);
    assert.equal(select.value, 'viewer', 'the select shows the role still applied');
    assert.equal(page.byId('keys-tbody').querySelector('[data-role-change]'), select, 'the last good list stays on screen');
    assert.equal(page.byId('keys-empty').style.display, 'none');
});

test('after an accepted role change whose list reload failed, a refused change restores the accepted role', async () => {
    let listing = () => reply(200, [KEY]), refuse = false;
    const page = await adminPage({
        routes: {
            'GET /api/admin/keys': () => listing(),
            'PUT /api/admin/keys/key_a1/permissions': () => (refuse ? reply(409, { detail: 'busy' }) : reply(200, {})),
        },
    });
    listing = () => reply(503, { detail: 'key store unavailable' });
    const select = page.byId('keys-tbody').querySelector('[data-role-change]');
    await page.change(select, 'analyst');
    assert.deepEqual(page.toasts(), [{ text: 'Could not load API keys: key store unavailable', type: 'error', markup: 0 }]);
    assert.equal(select.value, 'analyst');
    refuse = true;
    await page.change(select, 'admin');
    assert.equal(select.value, 'analyst', 'the role the server accepted, not the one it refused');
    assert.deepEqual(page.toasts().slice(1, 2), [{ text: 'Role change for key_a1 failed: busy', type: 'error', markup: 0 }]);
});

test('a role change refused for the session (401) or a key listing refused (401/403) goes to sign-in without an error toast', async () => {
    for (const [change, list] of [[401, 401], [401, 403], [403, 403]]) {
        const label = change + '/' + list;
        let listing = () => reply(200, [KEY]);
        const page = await adminPage({
            routes: {
                'GET /api/admin/keys': () => listing(),
                'PUT /api/admin/keys/key_a1/permissions': () => reply(change, { detail: 'Not authenticated' }),
            },
        });
        listing = () => reply(list, { detail: 'Not authenticated' });
        const select = page.byId('keys-tbody').querySelector('[data-role-change]');
        await page.change(select, 'admin');
        assert.equal(select.value, 'viewer');
        if (change === 401) assert.deepEqual(page.toasts(), [], label);
        // A refused change (403) is reported; the list it reloads then ends the session.
        else assert.deepEqual(page.toasts(), [{ text: 'Role change for key_a1 failed: Not authenticated', type: 'error', markup: 0 }], label);
        assert.deepEqual(page.redirects, ['/login?next=%2Fadmin'], label);
    }
});

test('a role change the server refuses with 403 (role ceiling) says why and keeps the operator signed in', async () => {
    const ceiling = 'Cannot change a key with role keymaster: above your own role (admin)';
    const keymaster = { ...KEY, key_id: 'key_km', role: 'keymaster', stored_role: 'keymaster' };
    let changes = 0;
    const page = await adminPage({
        routes: {
            'GET /api/admin/keys': () => reply(200, [keymaster, KEY]),
            'PUT /api/admin/keys/key_km/permissions': () => { changes++; return reply(403, { detail: ceiling }); },
        },
    });
    const listings = () => page.requests.filter(r => r.url === '/api/admin/keys').length;
    const before = listings();
    const select = page.byId('keys-tbody').querySelector('[data-role-change="key_km"]');
    assert.equal(select.value, 'keymaster', 'a keymaster key shows its own role');
    assert.deepEqual(select.querySelectorAll('option').map(option => option.value),
        ['keymaster', 'sensor', 'node', 'viewer', 'analyst', 'admin']);
    assert.ok(!page.byId('keys-tbody').querySelector('[data-role-change="key_a1"] option[value="keymaster"]'),
        'keymaster is offered only for the key that already holds it');
    await page.change(select, 'viewer');
    assert.equal(changes, 1);
    assert.deepEqual(page.toasts(), [{ text: 'Role change for key_km failed: ' + ceiling, type: 'error', markup: 0 }]);
    assert.deepEqual(page.redirects, [], 'the session is still good');
    assert.equal(page.byId('keys-tbody').querySelector('[data-role-change="key_km"]').value, 'keymaster', 'the role still in effect');
    assert.equal(listings(), before + 1, 'the list is reloaded');
});

test('a new raw key is only in the reveal dialog, as text, until acknowledged, then gone from the page', async () => {
    const raw = 'sk_<i>raw</i>&secret"value';
    const page = await adminPage({ routes: { 'POST /api/admin/keys': () => reply(201, { key_id: 'key_new', raw_key: raw }) } });
    await page.input(page.byId('new-key-desc'), '  rooftop sensor  ');
    page.byId('new-key-role').value = 'sensor';
    await page.input(page.byId('new-key-expires'), '30');
    await page.click(page.byId('create-key-btn'));

    const [write] = page.writes();
    assert.deepEqual(call(write), ['POST', '/api/admin/keys', { description: 'rooftop sensor', role: 'sensor', expires_days: 30 }]);
    assertCookieWrite(write);
    const display = page.byId('key-created-display');
    assert.equal(display.textContent, 'Key created. Key ID: key_new');
    assert.equal(page.byId('new-key-desc').value, '');
    assert.equal(page.byId('new-key-expires').value, '');

    const modal = page.modal();
    assertInert(modal, 'reveal dialog');
    const code = modal.querySelector('#admin-rawkey-code');
    assert.equal(code.textContent, raw);
    const done = page.button('Done');
    assert.equal(done.disabled, true, 'Done waits for the acknowledgement');
    await page.click(done);
    assert.equal(page.modal(), modal, 'Done does not close the dialog before acknowledging');

    await page.click(modal.querySelector('#admin-rawkey-copy'));
    assert.deepEqual(page.clipboard, [raw]);

    const ack = modal.querySelector('#admin-rawkey-ack');
    ack.checked = true;
    ack.dispatchEvent(new FakeEvent('change'));
    assert.equal(code.textContent, '•'.repeat(raw.length));
    assert.equal(done.disabled, false);
    await page.click(done);
    assert.equal(page.modal(), null);
    assert.equal(code.textContent, '', 'the closed dialog keeps neither the key nor its mask');
    const htmlNow = page.doc.documentElement.outerHTML;
    for (const form of [raw, escapeText(raw), 'sk_']) assert.ok(!htmlNow.includes(form), 'the raw key is no longer in the page');
});

test('a failed key creation shows the server reason as text and reveals nothing', async () => {
    const page = await adminPage({ routes: { 'POST /api/admin/keys': () => reply(503, { detail: MARKUP }) } });
    await page.click(page.byId('create-key-btn'));
    assert.deepEqual(page.writes().map(call), [['POST', '/api/admin/keys', { description: '', role: 'sensor' }]]);
    assert.deepEqual(page.toasts(), [{ text: 'Key creation failed: ' + MARKUP, type: 'error', markup: 0 }]);
    assert.equal(page.modal(), null);
    assert.equal(page.byId('key-created-display').innerHTML, '');
});

test('rotating a node-linked key: dismissing rotates nothing; each choice sends its deploy flag', async () => {
    const page = await adminPage({
        routes: {
            'GET /api/admin/keys': () => reply(200, [KEY]),
            'POST /api/admin/keys/key_a1/rotate': request => reply(200, request.body.deploy_to_node
                ? { key_id: 'key_a1', raw_key: 'sk_rotated_1', deployed: true, deploy_node_id: MARKUP, deploy_host: MARKUP }
                : { key_id: 'key_a1', raw_key: 'sk_rotated_2', deployed: false, deploy_error: MARKUP }),
        },
    });
    const rotate = () => page.click(page.byId('keys-tbody').querySelector('[data-rotate]'));
    await rotate();
    assertInert(page.modal(), 'rotate dialog');
    assert.match(page.modal().textContent, /Rotating key key_a1 linked to node edge-1\./);
    assert.deepEqual(page.modal().querySelectorAll('button').map(b => b.textContent),
        ['Cancel', 'Rotate Only (deploy manually)', 'Rotate & Deploy via SSH']);
    await page.click(page.button('Cancel'));
    await rotate();
    await page.key('Escape');
    assert.deepEqual(page.writes(), []);

    await rotate();
    await page.click(page.button('Rotate & Deploy via SSH'));
    let reveal = page.modal();
    assertInert(reveal, 'rotated key dialog');
    assert.match(reveal.textContent, /Deployed to node <img src=x onerror="alert\(1\)">/);
    const result = page.byId('key-rotate-result');
    assertInert(result, 'rotation result');
    assert.equal(result.textContent, 'Key rotated. Key ID: key_a1 — deployed to ' + MARKUP + '.');
    await page.acknowledge(true);
    await page.click(page.button('Done'));

    await rotate();
    await page.click(page.button('Rotate Only (deploy manually)'));
    reveal = page.modal();
    assertInert(reveal, 'rotated key dialog');
    assert.match(reveal.textContent, /Deploy failed: <img src=x/);
    assert.equal(result.textContent, 'Key rotated. Key ID: key_a1 — deploy failed: ' + MARKUP);
    assert.ok(!result.textContent.includes('sk_rotated'), 'the inline result never shows the raw key');

    const writes = page.writes();
    assert.deepEqual(writes.map(call), [
        ['POST', '/api/admin/keys/key_a1/rotate', { deploy_to_node: true }],
        ['POST', '/api/admin/keys/key_a1/rotate', { deploy_to_node: false }],
    ]);
    writes.forEach(w => assertCookieWrite(w));
});

test('rotating an unlinked key offers only rotation; a failure explains why as text', async () => {
    const page = await adminPage({
        routes: {
            'GET /api/admin/keys': () => reply(200, [{ ...KEY, node_id: null }]),
            'POST /api/admin/keys/key_a1/rotate': () => reply(500, { detail: MARKUP }),
        },
    });
    await page.click(page.byId('keys-tbody').querySelector('[data-rotate]'));
    assert.deepEqual(page.modal().querySelectorAll('button').map(b => b.textContent), ['Cancel', 'Rotate Key']);
    await page.click(page.button('Rotate Key'));
    assert.deepEqual(page.writes().map(call), [['POST', '/api/admin/keys/key_a1/rotate', { deploy_to_node: false }]]);
    const result = page.byId('key-rotate-result');
    assertInert(result, 'rotation failure');
    assert.equal(result.textContent, 'Rotation failed: ' + MARKUP);
    assert.deepEqual(page.toasts(), [{ text: 'Key rotation failed: ' + MARKUP, type: 'error', markup: 0 }]);
    assert.equal(page.modal(), null);
});

const RAW = 'sk_fixture_0123456789abcdef';

test('an unacknowledged new key stays on screen through Escape and a click outside the dialog', async () => {
    const page = await adminPage({ routes: { 'POST /api/admin/keys': () => reply(201, { key_id: 'key_new', raw_key: RAW }) } });
    await page.click(page.byId('create-key-btn'));
    const modal = page.modal();
    await page.key('Escape');
    assert.equal(page.modal(), modal, 'Escape keeps the unacknowledged key on screen');
    const backdrop = page.doc.querySelector('.admin-modal-backdrop');
    backdrop.dispatchEvent(new FakeEvent('mousedown', { target: backdrop }));
    await settle();
    assert.equal(page.modal(), modal, 'a click outside keeps it on screen');
    assert.equal(modal.querySelector('#admin-rawkey-code').textContent, RAW);
});

test('once the new key is acknowledged, Escape closes the reveal and clears the key', async () => {
    const page = await adminPage({ routes: { 'POST /api/admin/keys': () => reply(201, { key_id: 'key_new', raw_key: RAW }) } });
    await page.click(page.byId('create-key-btn'));
    const code = page.modal().querySelector('#admin-rawkey-code');
    await page.acknowledge(true);
    await page.key('Escape');
    assert.equal(page.modal(), null);
    assert.equal(code.textContent, '', 'the dismissed dialog no longer carries the key');
});

test('the reveal dialog: un-acknowledging shows the key again and locks Done; a refused copy says so', async () => {
    const page = await adminPage({
        clipboard: 'refuse',
        routes: {
            'GET /api/admin/keys': () => reply(200, [{ ...KEY, node_id: null }]),
            'POST /api/admin/keys/key_a1/rotate': () => reply(200, { key_id: 'key_a1', raw_key: RAW }),
        },
    });
    await page.click(page.byId('keys-tbody').querySelector('[data-rotate]'));
    await page.click(page.button('Rotate Key'));
    assert.equal(page.byId('key-rotate-result').textContent, 'Key rotated. Key ID: key_a1');
    const modal = page.modal(), code = modal.querySelector('#admin-rawkey-code'), done = page.button('Done');
    assert.equal(modal.querySelector('.admin-modal-title').textContent, 'Key rotated — save the new key now');
    await page.acknowledge(true);
    assert.equal(done.disabled, false);
    await page.acknowledge(false);
    assert.equal(code.textContent, RAW, 'unticking shows the key again');
    assert.equal(done.disabled, true, 'and Done waits for the acknowledgement again');

    const copy = modal.querySelector('#admin-rawkey-copy');
    await page.click(copy);
    assert.equal(copy.textContent, 'Copy failed', 'a refused clipboard is not reported as copied');
    await page.advance(10_000);
    assert.equal(copy.textContent, 'Copy', 'the label comes back');
    assert.deepEqual(page.clipboard, []);
});

for (const [copied, label] of [[true, 'Copied!'], [false, 'Copy failed']]) {
    test('without the Clipboard API the key is copied through a temporary field that is removed at once (' + label + ')', async () => {
        const page = await adminPage({
            clipboard: 'absent', execCommand: copied,
            routes: { 'POST /api/admin/keys': () => reply(201, { key_id: 'key_new', raw_key: RAW }) },
        });
        await page.click(page.byId('create-key-btn'));
        const modal = page.modal(), copy = modal.querySelector('#admin-rawkey-copy');
        const fields = page.doc.querySelectorAll('textarea').length;
        await page.click(copy);
        assert.deepEqual(page.copies, [['copy', RAW]], 'the key is copied from a field in the page');
        assert.equal(copy.textContent, label);
        assert.deepEqual(page.doc.querySelectorAll('textarea').filter(field => field.value === RAW), [], 'no field keeps the key');
        assert.equal(page.doc.querySelectorAll('textarea').length, fields, 'the temporary field is removed');
        assert.equal(page.modal(), modal, 'the dialog stays open');
    });
}

/* ------------------------------------------------------------------ */
/* Client certificates                                                 */
/* ------------------------------------------------------------------ */

test('certificate list: identities and serials render as text; only unrevoked certificates can be revoked', async () => {
    const page = await adminPage({
        routes: {
            'GET /api/ca/certs': () => reply(200, [
                { ...CERT, identity: MARKUP, serial: ATTR_MARKUP + '0123456789' },
                { ...CERT, identity: 'old', serial: 'aa', revoked: true },
                { ...CERT, identity: 'lapsed', serial: 'bb', not_after: '2026-01-01T00:00:00Z' },
                { revoked: true },
            ]),
        },
    });
    const tbody = page.byId('certs-tbody');
    assertInert(tbody, 'certificate list');
    const [valid, revoked, expired, sparse] = tbody.querySelectorAll('tr');
    assert.deepEqual(['Identity', 'Role', 'Serial', 'Status', 'Actions'].map(label => cell(sparse, label).textContent),
        ['--', 'NODE', '', 'REVOKED', '--'], 'a record without identity, role or serial still renders');
    assert.equal(cell(valid, 'Identity').textContent, MARKUP);
    assert.equal(cell(valid, 'Serial').textContent, (ATTR_MARKUP + '0123456789').slice(0, 16));
    assert.equal(valid.querySelector('[data-revoke-cert]').getAttribute('data-revoke-cert'), ATTR_MARKUP + '0123456789');
    assert.equal(cell(valid, 'Status').textContent, 'VALID');
    assert.equal(cell(revoked, 'Status').textContent, 'REVOKED');
    assert.equal(revoked.querySelectorAll('button').length, 0);
    assert.equal(cell(expired, 'Status').textContent, 'EXPIRED');
    assert.equal(expired.querySelector('[data-revoke-cert]').getAttribute('data-revoke-cert'), 'bb');
    assert.equal(page.byId('certs-empty').style.display, 'none');
});

test('revoking a certificate needs confirmation; a refusal is shown as text', async () => {
    let refuse = false;
    const page = await adminPage({
        routes: {
            'GET /api/ca/certs': () => reply(200, [CERT]),
            ['POST /api/ca/revoke/' + CERT.serial]: () => (refuse ? reply(503, { detail: MARKUP }) : reply(200, { revoked: true })),
        },
    });
    const revoke = () => page.click(page.byId('certs-tbody').querySelector('[data-revoke-cert]'));
    await revoke();
    assert.match(page.modal().textContent, new RegExp('Revoke certificate ' + CERT.serial + '\\?'));
    await page.click(page.button('Cancel'));
    assert.deepEqual(page.writes(), []);
    await revoke();
    await page.click(page.button('Revoke'));
    const [write] = page.writes();
    assert.deepEqual(call(write), ['POST', '/api/ca/revoke/' + CERT.serial, undefined]);
    assertCookieWrite(write, { json: false });
    assert.deepEqual(page.toasts(), [{ text: 'Certificate revoked', type: 'success', markup: 0 }]);
    assert.equal(page.requests.filter(r => r.url === '/api/ca/certs').length, 2);

    refuse = true;
    await revoke();
    await page.click(page.button('Revoke'));
    assert.deepEqual(page.toasts().at(-1), { text: 'Failed to revoke: ' + MARKUP, type: 'error', markup: 0 });
});

test('minting a certificate: a blank identity is refused before sending', async () => {
    const page = await adminPage();
    await page.input(page.byId('new-cert-identity'), '   ');
    await page.click(page.byId('mint-cert-btn'));
    assert.deepEqual(page.writes(), []);
    assert.deepEqual(page.toasts(), [{ text: 'Enter a certificate identity', type: 'error', markup: 0 }]);
});

for (const [ttl, sent] of [['30', 30], ['0', 90], ['-5', 90], ['abc', 90], ['', 90]]) {
    test('minting a certificate: lifetime ' + JSON.stringify(ttl) + ' is sent as ' + sent + ' days', async () => {
        const page = await adminPage({ routes: { 'POST /api/ca/issue': () => reply(201, { identity: 'edge-2', cert_pem: 'c', key_pem: 'k', ca_pem: 'a' }) } });
        await page.input(page.byId('new-cert-identity'), ' edge-2 ');
        page.byId('new-cert-role').value = 'sensor';
        await page.input(page.byId('new-cert-ttl'), ttl);
        await page.click(page.byId('mint-cert-btn'));
        const [write] = page.writes();
        assert.deepEqual(call(write), ['POST', '/api/ca/issue', { identity: 'edge-2', role: 'sensor', ttl_days: sent }]);
        assertCookieWrite(write);
    });
}

test('a minted private key is offered only as a download, never written into the page', async () => {
    const keyPem = '-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIFixture\n-----END PRIVATE KEY-----\n';
    const page = await adminPage({
        routes: { 'POST /api/ca/issue': () => reply(201, { identity: MARKUP, cert_pem: 'CERT PEM', key_pem: keyPem, ca_pem: 'CA PEM' }) },
    });
    await page.input(page.byId('new-cert-identity'), 'edge-2');
    await page.click(page.byId('mint-cert-btn'));
    const display = page.byId('cert-minted-display');
    assertInert(display, 'issued certificate notice');
    assert.equal(display.style.display, '');
    assert.match(display.textContent, /^Certificate issued for <img src=x onerror="alert\(1\)">/);
    const links = display.querySelectorAll('a');
    assert.deepEqual(links.map(a => [a.textContent, a.download, a.href]), [
        ['Download certificate', MARKUP + '.crt', 'blob:admin/1'],
        ['Download private key', MARKUP + '.key', 'blob:admin/2'],
        ['Download CA certificate', 'ca.crt', 'blob:admin/3'],
    ]);
    assert.deepEqual(await Promise.all(page.blobs.map(b => b.text())), ['CERT PEM', keyPem, 'CA PEM']);
    assert.ok(!page.doc.documentElement.outerHTML.includes('PRIVATE KEY'), 'the private key is not in the DOM');
    assert.equal(page.byId('new-cert-identity').value, '');
    assert.deepEqual(page.toasts(), [{ text: 'Certificate issued for ' + MARKUP, type: 'success', markup: 0 }]);
});

for (const status of [400, 503]) {
    test('a refused certificate (' + status + ') shows the server reason as text', async () => {
        const page = await adminPage({ routes: { 'POST /api/ca/issue': () => reply(status, { detail: MARKUP }) } });
        await page.input(page.byId('new-cert-identity'), 'edge-2');
        await page.click(page.byId('mint-cert-btn'));
        assert.deepEqual(page.toasts(), [{ text: 'Mint failed: ' + MARKUP, type: 'error', markup: 0 }]);
        assert.equal(page.byId('cert-minted-display').innerHTML, '');
        assert.equal(page.byId('new-cert-identity').value, 'edge-2', 'the identity stays to correct');
    });
}

/* ------------------------------------------------------------------ */
/* Nodes: commands, config and diagnostics                             */
/* ------------------------------------------------------------------ */

function nodesRoutes(extra = {}) {
    return { 'GET /api/admin/nodes': () => reply(200, [NODE]), ...extra };
}

test('node list: hosts and heartbeat errors render as text; node ids round-trip', async () => {
    const page = await adminPage({
        routes: nodesRoutes({
            'GET /api/admin/nodes': () => reply(200, [
                { ...NODE, node_id: ATTR_MARKUP, host: MARKUP, cpu_percent: 95, capabilities: { last_error: MARKUP, cpu_temp: 82 } },
            ]),
        }),
    });
    await page.tab('nodes');
    const tbody = page.byId('admin-nodes-tbody');
    assertInert(tbody, 'node list');
    const row = tbody.querySelector('tr');
    assert.equal(cell(row, 'Host').textContent, MARKUP);
    assert.equal(cell(row, 'Node').textContent, ATTR_MARKUP);
    for (const action of ['data-node-detail', 'data-restart-scanner', 'data-update-config', 'data-run-diag', 'data-dereg']) {
        assert.equal(tbody.querySelector('[' + action + ']').getAttribute(action), ATTR_MARKUP, action);
    }
    assert.equal(row.querySelector('.node-health').textContent.trim(), 'Critical');
    const alerts = page.byId('fleet-alerts-container');
    assertInert(alerts, 'fleet alerts');
    assert.equal(alerts.textContent, ATTR_MARKUP + ': CPU 95.0%, Temp 82°C, ' + MARKUP.substring(0, 60));
    const option = page.byId('admin-fp-node-select').querySelectorAll('option').at(-1);
    assert.deepEqual([option.value, option.textContent], [ATTR_MARKUP, ATTR_MARKUP]);
});

test('restarting or deregistering a node needs confirmation; each is one encoded request', async () => {
    const page = await adminPage({
        routes: nodesRoutes({
            'POST /api/admin/nodes/edge_1/command': () => reply(200, { queued: true }),
            'DELETE /api/admin/nodes/edge_1': () => reply(409, { detail: MARKUP }),
        }),
    });
    await page.tab('nodes');
    const tbody = page.byId('admin-nodes-tbody');
    const details = () => [page.byId('node-detail-modal').style.display, page.requests.filter(r => r.url.endsWith('/diagnostics')).length];
    for (const action of ['[data-restart-scanner]', '[data-dereg]', '[data-update-config]']) {
        await page.click(tbody.querySelector(action));
        assert.ok(page.modal(), action + ' asks first');
        assert.deepEqual(details(), ['none', 0], action + ' does not also open the row details');
        await page.click(page.button('Cancel'));
        await page.click(tbody.querySelector(action));
        await page.key('Escape');
    }
    assert.deepEqual(page.writes(), []);

    await page.click(tbody.querySelector('[data-restart-scanner]'));
    assert.match(page.modal().textContent, /Restart every service on edge_1, including its agent\?/);
    await page.click(page.button('Restart'));
    await page.click(tbody.querySelector('[data-dereg]'));
    assert.match(page.modal().textContent, /This cannot be undone\./);
    await page.click(page.button('Deregister'));

    const writes = page.writes();
    assert.deepEqual(writes.map(call), [
        ['POST', '/api/admin/nodes/edge_1/command', { command: 'restart', params: {} }],
        ['DELETE', '/api/admin/nodes/edge_1', undefined],
    ]);
    assertCookieWrite(writes[0]);
    assertCookieWrite(writes[1], { json: false });
    assert.deepEqual(page.toasts(), [
        { text: 'Restart command queued for edge_1', type: 'success', markup: 0 },
        { text: 'Failed to deregister node: ' + MARKUP, type: 'error', markup: 0 },
    ]);
});

test('pushing node config: invalid JSON is never sent; valid JSON is sent as an object', async () => {
    const page = await adminPage({ routes: nodesRoutes({ 'PUT /api/admin/nodes/edge_1/config': () => reply(200, {}) }) });
    await page.tab('nodes');
    await page.click(page.byId('admin-nodes-tbody').querySelector('[data-update-config]'));
    const modal = page.modal();
    assert.equal(modal.querySelector('.admin-modal-title').textContent, 'Push config to edge_1');
    const textarea = modal.querySelector('#admin-modal-cfg-json'), error = modal.querySelector('#admin-modal-cfg-err');
    assert.equal(textarea.value, '{}');
    assert.equal(error.style.display, 'none');

    await page.input(textarea, '{"scan_interval": 5,');
    assert.equal(error.style.display, '');
    assert.match(error.textContent, /^Invalid JSON: /);
    await page.click(page.button('Submit'));
    assert.equal(page.modal(), modal, 'the dialog stays open on invalid JSON');
    await page.input(textarea, '   ');
    assert.equal(error.textContent, 'Empty input — provide a JSON object (e.g. {}).');
    await page.click(page.button('Submit'));
    assert.deepEqual(page.writes(), []);

    await page.input(textarea, '{"scan_interval": 5, "note": "<b>x</b>"}');
    assert.equal(error.style.display, 'none');
    await page.click(page.button('Submit'));
    assert.equal(page.modal(), null);
    const [write] = page.writes();
    assert.deepEqual(call(write), ['PUT', '/api/admin/nodes/edge_1/config', { config: { scan_interval: 5, note: '<b>x</b>' } }]);
    assertCookieWrite(write);
    assert.deepEqual(page.toasts(), [{ text: 'Config update queued for edge_1', type: 'success', markup: 0 }]);
});

test('node diagnostics: every heartbeat-reported string renders as text', async () => {
    // Each reported string is markup tagged with its field, so each one is found on its own.
    const reported = [];
    const s = field => { const value = '[' + field + '] ' + MARKUP; reported.push(value); return value; };
    const diagnostics = {
        health: 'red', health_issues: [s('issue')],
        system_info: { cpu_percent: 99, os: s('os'), platform: s('platform'), python_version: s('python'), agent_version: s('agent'), model: s('model'), accelerator: s('accelerator') },
        sdr_info: { type: s('sdr type'), capture_mode: s('capture mode'), serial: s('serial'), firmware: s('firmware'), sample_rate: 2.4e6 },
        detection_stats: { total_detections: 3, dominant_class: s('dominant class'), dominant_family: s('dominant family'), top_classes: [{ class: s('top class'), count: 3 }] },
        scanners: [{ name: s('scanner'), status: s('scanner status'), count: 2 }],
        recent_errors: [{ timestamp: '2026-11-10T11:00:00Z', action: s('error action'), note: s('error note') }],
        pending_commands: [{ command: s('command'), queued_at: '2026-11-10T11:30:00Z' }],
        latency_ms: 12.4,
    };
    const page = await adminPage({ routes: nodesRoutes({ 'GET /api/admin/nodes/edge_1/diagnostics': () => reply(200, diagnostics) }) });
    await page.tab('nodes');
    await page.click(page.byId('admin-nodes-tbody').querySelector('[data-run-diag]'));
    const body = page.byId('node-detail-body');
    assertInert(body, 'node diagnostics');
    assert.equal(page.byId('node-detail-modal').style.display, '');
    assert.equal(page.byId('node-detail-title').textContent, 'Node Diagnostics: edge_1');
    for (const value of reported) assert.ok(body.textContent.includes(value), value.slice(0, value.indexOf(']') + 1) + ' is shown literally');
    assert.match(body.textContent, /Health: RED/);
    await page.key('Escape');
    assert.equal(page.byId('node-detail-modal').style.display, 'none');
});

test('a failed diagnostics load explains why as text', async () => {
    const page = await adminPage({ routes: nodesRoutes({ 'GET /api/admin/nodes/edge_1/diagnostics': () => reply(503, { detail: MARKUP }) }) });
    await page.tab('nodes');
    await page.click(page.byId('admin-nodes-tbody').querySelector('tr'));
    const body = page.byId('node-detail-body');
    assertInert(body, 'diagnostics failure');
    assert.equal(body.textContent, 'Failed to load diagnostics: ' + MARKUP);
});

test('node diagnostics: a node that reports nothing gets placeholders, never "undefined"', async () => {
    const answers = [{ health: 'yellow' }, { health: 'green', recent_errors: [{}] }];
    const page = await adminPage({ routes: nodesRoutes({ 'GET /api/admin/nodes/edge_1/diagnostics': () => reply(200, answers.shift()) }) });
    await page.tab('nodes');
    const body = page.byId('node-detail-body');
    await page.click(page.byId('admin-nodes-tbody').querySelector('[data-run-diag]'));
    assertInert(body, 'sparse diagnostics');
    const values = body.querySelectorAll('.ndv').map(value => value.textContent);
    assert.ok(values.length > 0, 'the diagnostics fields are shown');
    assert.deepEqual(values.filter(value => value !== '--' && value !== 'None'), [], 'every unreported field shows a placeholder');
    assert.match(body.textContent, /^Health: YELLOW/);
    assert.match(body.textContent, /No active scanners/);
    assert.match(body.textContent, /Recent Audit\/Log Entries \(0\)No recent entries/);
    assert.doesNotMatch(body.textContent, /undefined|null|NaN/);

    await page.click(page.byId('admin-nodes-tbody').querySelector('[data-run-diag]'));
    assert.match(body.textContent, /Recent Audit\/Log Entries \(1\)--: $/);
    assert.doesNotMatch(body.textContent, /undefined|null|NaN/);
});

// scanners[].count is copied from scan_count/anomaly_count, free-form NodeMetrics
// extras that a node-bound sensor key sets by heartbeat.
test('node diagnostics: a heartbeat-reported scanner count renders as text', async () => {
    const page = await adminPage({
        routes: nodesRoutes({
            'GET /api/admin/nodes/edge_1/diagnostics': () => reply(200, { health: 'green', scanners: [{ name: 'RF Scanner', status: 'active', count: MARKUP }] }),
        }),
    });
    await page.tab('nodes');
    await page.click(page.byId('admin-nodes-tbody').querySelector('[data-run-diag]'));
    const body = page.byId('node-detail-body');
    assertInert(body, 'node diagnostics');
    assert.match(body.textContent, /RF Scanner — active \(<img src=x onerror="alert\(1\)">/);
});

test('one node reporting a non-numeric temperature does not hide the fleet from the admin', async () => {
    const page = await adminPage({
        routes: nodesRoutes({ 'GET /api/admin/nodes': () => reply(200, [{ ...NODE, node_id: 'edge_2', capabilities: { cpu_temp: 'n/a' } }, NODE]) }),
    });
    await page.tab('nodes');
    assert.deepEqual(page.byId('admin-nodes-tbody').querySelectorAll('tr').map(row => cell(row, 'Node').textContent), ['edge_2', 'edge_1']);
});

// Older bridges stored heartbeat values unchecked, and admin-registered
// capabilities are free-form: every number the node views format is read
// as not reported when it is not a finite number.
test('node values of another type read as not reported in the node table, fleet overview and diagnostics', async () => {
    const odd = {
        ...NODE, node_id: 'edge_2', cpu_percent: '95', memory_mb: [512], classifications_per_sec: 'fast',
        detection_summary: { total_detections: '10', period_seconds: {} },
        capabilities: { cpu_temp: { celsius: 90 }, uptime_seconds: 'long', last_error: 42 },
    };
    const diagnostics = {
        health: 'green', uptime_seconds: '1h', latency_ms: '12',
        system_info: { cpu_percent: '9', memory_mb: [1], disk_percent: 'full', cpu_temp: 'hot', load_1m: true },
        detection_stats: { total_detections: 1, rate_per_min: '5', avg_confidence: 'high', period_seconds: 'x' },
    };
    const page = await adminPage({
        routes: nodesRoutes({
            'GET /api/admin/nodes': () => reply(200, [odd, NODE]),
            'GET /api/admin/nodes/edge_2/diagnostics': () => reply(200, diagnostics),
        }),
    });
    await page.tab('nodes');
    const [row, good] = page.byId('admin-nodes-tbody').querySelectorAll('tr');
    for (const label of ['Det/min', 'CPU', 'Mem', 'Temp', 'Uptime']) assert.equal(cell(row, label).textContent, '--', label);
    assert.equal(row.querySelector('.node-health').textContent.trim(), 'Healthy');
    assert.deepEqual(['CPU', 'Mem', 'Temp', 'Uptime'].map(label => cell(good, label).textContent), ['12.5', '512', '50°C', '1h 0m']);
    // Only the numbers count toward the fleet figures; the error still flags the node.
    assert.deepEqual(['fleet-total', 'fleet-avg-cpu', 'fleet-avg-mem', 'fleet-det-rate', 'fleet-degraded'].map(id => page.byId(id).textContent),
        ['2', '12.5', '512', '0.0', '1']);
    assert.equal(page.byId('fleet-alerts-container').textContent, 'edge_2: 42');

    await page.click(row.querySelector('[data-run-diag]'));
    const body = page.byId('node-detail-body');
    const shown = {};
    for (const item of body.querySelectorAll('.node-detail-item')) shown[item.querySelector('.ndl').textContent] = item.querySelector('.ndv').textContent;
    for (const label of ['CPU', 'Memory', 'Disk', 'Temperature', 'Load 1m', 'Uptime', 'Rate', 'Avg Confidence', 'Period']) {
        assert.equal(shown[label], '--', label);
    }
    assert.equal(shown['Total Detections'], '1');
    assert.ok(!('Heartbeat Latency' in shown), 'a latency that is not a number is not shown');
    assert.doesNotMatch(body.textContent, /NaN|undefined/);
});

/* ------------------------------------------------------------------ */
/* Audit log                                                           */
/* ------------------------------------------------------------------ */

test('audit log: actors, notes and details render as text in the table, filters and detail view', async () => {
    const entries = [
        { timestamp: '2026-11-10T11:00:00Z', action: MARKUP, target_id: MARKUP, operator: MARKUP, note: MARKUP,
            details: { username: MARKUP, [ATTR_MARKUP]: 'k', severity: 'warning' } },
        { timestamp: '2026-11-10T11:01:00Z', action: 'config_change', target_id: 't', operator: 'admin',
            target_ids: [MARKUP, 'b'], details: { changes: [{ key: MARKUP, old: MARKUP, new: null }] } },
    ];
    const page = await adminPage({
        routes: {
            'GET /api/admin/audit/filters': () => reply(200, { actions: [MARKUP], operators: [MARKUP], node_ids: [ATTR_MARKUP] }),
            'GET /api/admin/audit': () => reply(200, { entries }),
        },
    });
    await page.tab('audit');
    assert.ok(page.requests.some(r => r.url === '/api/admin/audit?limit=50&offset=0'));
    const tbody = page.byId('audit-tbody');
    assertInert(tbody, 'audit table');
    const [first, second] = tbody.querySelectorAll('tr');
    for (const label of ['Action', 'Target', 'Operator', 'Note']) assert.equal(cell(first, label).textContent, MARKUP, label);
    assert.match(cell(first, 'Details').textContent, /^username: <img src=x onerror="alert\(1\)"><script\.\.\.; <b onmouseover=alert\(3\)>id&amp;<\/b>: k; severity: warning View$/);
    assert.equal(cell(second, 'Details').textContent, '1 change View');
    for (const id of ['audit-action-filter', 'audit-operator-filter', 'audit-node-filter']) {
        assertInert(page.byId(id), id);
        assert.ok(page.byId(id).options.some(o => o.textContent === MARKUP || o.textContent === ATTR_MARKUP), id);
    }

    for (const [index, entry] of entries.entries()) {
        await page.click(tbody.querySelectorAll('[data-audit-idx]')[index]);
        const modal = page.byId('audit-detail-modal');
        assert.equal(modal.style.display, '');
        assertInert(page.byId('audit-detail-body'), 'audit detail');
        assert.equal(page.byId('audit-detail-title').textContent, 'Audit: ' + entry.action);
        assert.equal(modal.getAttribute('data-json'), JSON.stringify(entry, null, 2));
        assert.ok(page.byId('audit-detail-body').textContent.includes(MARKUP));
    }
});

/* ------------------------------------------------------------------ */
/* Condition rules (analysts create them; admins review them here)     */
/* ------------------------------------------------------------------ */

function rule(value, extra = {}) {
    return {
        rule_id: 'rule_1', name: '&lt;img src=x onerror=alert(1)&gt;', severity: 'warning', enabled: true,
        cooldown_seconds: 300, trigger_count: 0, conditions: [{ field: 'signal_class', operator: 'eq', value }], ...extra,
    };
}

test('condition rules: names and values without quotes render as text in the list and the edit form', async () => {
    const value = '<img src=x onerror=alert(1)>&amp;';
    const page = await adminPage({
        routes: { 'GET /api/admin/alerts': () => reply(200, []), 'GET /api/alerts/rules/conditions': () => reply(200, [rule(value)]) },
    });
    await page.tab('alerts');
    const tbody = page.byId('condition-rules-tbody');
    assertInert(tbody, 'condition rules');
    assert.equal(cell(tbody, 'Name').textContent, '<img src=x onerror=alert(1)>');
    assert.equal(cell(tbody, 'Conditions').textContent, 'signal_class eq ' + value);
    // The hover title is the same text, escaped once for its attribute.
    assert.equal(cell(tbody, 'Conditions').getAttribute('title'), 'signal_class eq ' + value);
    await page.click(tbody.querySelector('[data-edit-crule]'));
    assertInert(page.byId('condition-rows'), 'condition edit form');
    assert.equal(page.byId('condition-rows').querySelector('.cond-val').value, value);
    assert.equal(page.byId('condition-rule-name').value, '<img src=x onerror=alert(1)>');
});

// An analyst sets the value; it lands in title="..." in the list and in
// value="..." in the edit form.
test('condition rules: a value with a double quote cannot add attributes to the admin page', async () => {
    const value = 'x" style="position:fixed;inset:0" onmouseover="alert(document.cookie)';
    const page = await adminPage({
        routes: { 'GET /api/admin/alerts': () => reply(200, []), 'GET /api/alerts/rules/conditions': () => reply(200, [rule(value)]) },
    });
    await page.tab('alerts');
    const tbody = page.byId('condition-rules-tbody');
    assertInert(tbody, 'condition rules');
    assert.equal(cell(tbody, 'Conditions').textContent, 'signal_class eq ' + value);
    assert.equal(cell(tbody, 'Conditions').getAttribute('title'), 'signal_class eq ' + value);
    await page.click(tbody.querySelector('[data-edit-crule]'));
    assertInert(page.byId('condition-rows'), 'condition edit form');
    assert.equal(page.byId('condition-rows').querySelector('.cond-val').value, value, 'the edit field holds the whole value');
});

/* ------------------------------------------------------------------ */
/* Database maintenance                                                */
/* ------------------------------------------------------------------ */

function databaseRoutes(extra = {}) {
    return {
        'GET /api/admin/stats': () => reply(200, { table_stats: [], tables: {} }),
        'GET /api/admin/jobs': () => reply(200, { jobs: [] }),
        'GET /api/admin/backups': () => reply(200, { backups: [] }),
        ...extra,
    };
}

test('a destructive purge runs only after its dataset phrase is typed', async () => {
    const page = await adminPage({
        routes: databaseRoutes({ 'POST /api/admin/maintenance': () => reply(200, { deleted: { [MARKUP]: 3 }, note: MARKUP }) }),
    });
    await page.tab('database');
    const purge = page.doc.querySelector('.maint-task-btn[data-task="purge_iq_captures"]');
    await page.click(purge);
    await page.click(page.button('Cancel'));
    await page.click(purge);
    assertInert(page.modal(), 'purge dialog');
    assert.match(page.modal().textContent, /permanently delete data for: Purge IQ Captures\.Retention window: 7 days\./);
    const del = page.button('Delete'), input = page.modal().querySelector('#maint-confirm-input');
    assert.equal(del.disabled, true);
    await page.click(del);
    await page.input(input, 'iq captur');
    assert.equal(del.disabled, true);
    await page.key('Enter', input);
    assert.deepEqual(page.writes(), [], 'nothing runs before the phrase matches');

    await page.input(input, '  IQ Captures ');
    assert.equal(del.disabled, false);
    await page.key('Enter', input);
    assert.equal(page.modal(), null);
    const [write] = page.writes();
    assert.deepEqual(call(write), ['POST', '/api/admin/maintenance', { task: 'purge_iq_captures', retention_days: 7 }]);
    assertCookieWrite(write);
    const result = page.byId('maint-result');
    assertInert(result, 'maintenance result');
    assert.equal(result.textContent, 'Purge IQ Captures completed.' + MARKUP + ': 3 removed' + MARKUP);
    assert.equal(purge.disabled, false);
    assert.equal(purge.textContent, 'Purge IQ Captures');
});

for (const [retention, days] of [['30', 30], ['0', 7], ['-5', 7], ['x', 7]]) {
    test('a purge sends retention ' + JSON.stringify(retention) + ' as ' + days + ' days', async () => {
        const page = await adminPage({ routes: databaseRoutes({ 'POST /api/admin/maintenance': () => reply(500, { detail: MARKUP }) }) });
        await page.tab('database');
        await page.input(page.byId('maint-retention'), retention);
        await page.click(page.doc.querySelector('.maint-task-btn[data-task="purge_detections"]'));
        await page.input(page.modal().querySelector('#maint-confirm-input'), 'detections');
        await page.click(page.button('Delete'));
        assert.deepEqual(page.writes().map(call), [['POST', '/api/admin/maintenance', { task: 'purge_detections', retention_days: days }]]);
        const result = page.byId('maint-result');
        assertInert(result, 'maintenance failure');
        assert.equal(result.textContent, 'Failed: ' + MARKUP);
    });
}

test('a non-destructive maintenance task still asks once', async () => {
    const page = await adminPage({ routes: databaseRoutes({ 'POST /api/admin/maintenance': () => reply(200, { vacuumed: true }) }) });
    await page.tab('database');
    const vacuum = page.doc.querySelector('.maint-task-btn[data-task="vacuum"]');
    await page.click(vacuum);
    assert.equal(page.modal().textContent.includes('Run "VACUUM (reclaim disk)"?'), true);
    await page.click(page.button('Cancel'));
    assert.deepEqual(page.writes(), []);
    await page.click(vacuum);
    await page.click(page.button('Run'));
    assert.deepEqual(page.writes().map(call), [['POST', '/api/admin/maintenance', { task: 'vacuum', retention_days: 7 }]]);
});

test('database statistics: row counts the server reports as text render as text', async () => {
    const stats = { table_stats: [{ name: 'detections', rows: MARKUP, rows_1h: MARKUP, rows_24h: 5, size_bytes: 10 }], tables: {}, db_path: 'd.db' };
    const page = await adminPage({ routes: databaseRoutes({ 'GET /api/admin/stats': () => reply(200, stats) }) });
    await page.tab('database');
    const el = page.byId('system-db-stats');
    assertInert(el, 'database statistics');
    const row = el.querySelector('tbody tr');
    assert.deepEqual(['Rows', '1h', '24h'].map(label => cell(row, label).textContent), [MARKUP, MARKUP, '5']);
    assert.match(el.querySelector('p').textContent, /^Total rows: 0<img src=x onerror="alert\(1\)">/);
});

/* ------------------------------------------------------------------ */
/* System: sessions and session binding                                */
/* ------------------------------------------------------------------ */

function systemRoutes(extra = {}) {
    return {
        'GET /api/metrics': () => reply(200, {}),
        'GET /api/admin/config': () => reply(200, { banner: MARKUP }),
        'GET /api/admin/sessions': () => reply(200, { sessions: [{ token_prefix: MARKUP, key_id: MARKUP, created: null, expires: null }] }),
        'GET /api/admin/session-binding': () => reply(200, { saved: 'none', gateway_active: MARKUP, restart_required: true }),
        ...extra,
    };
}

test('system tab: active sessions and configuration render as text', async () => {
    const page = await adminPage({ routes: systemRoutes() });
    await page.tab('system');
    const sessions = page.byId('system-sessions');
    assertInert(sessions, 'active sessions');
    assert.equal(cell(sessions, 'Token').textContent, MARKUP);
    assert.equal(cell(sessions, 'Key ID').textContent, MARKUP);
    assertInert(page.byId('system-config'), 'system config');
    assert.equal(page.byId('system-config').textContent, JSON.stringify({ banner: MARKUP }, null, 2));
});

test('session binding: the saved mode and gateway state are text; saving sends the mode with CSRF', async () => {
    let saves = 0;
    const page = await adminPage({
        routes: systemRoutes({
            'PUT /api/admin/session-binding': () => (saves++ ? reply(500, { detail: 'no' })
                : reply(200, { saved: 'ip', gateway_active: 'none', restart_required: true })),
        }),
    });
    await page.tab('system');
    const status = page.byId('session-binding-status');
    assert.equal(status.textContent, 'Saved preference: none • Gateway active: ' + MARKUP + ' • restart required ⚠');
    assert.equal(status.children.length, 0);
    assert.equal(page.byId('session-binding-gateway-value').textContent, MARKUP);
    assert.equal(page.byId('session-binding-restart-banner').style.display, 'block');
    assert.equal(page.byId('session-binding-mode').value, 'none');

    page.routes['GET /api/admin/session-binding'] = () => reply(200, { saved: 'ip', gateway_active: 'none', restart_required: true });
    page.byId('session-binding-mode').value = 'ip';
    await page.click(page.byId('session-binding-save-btn'));
    const [write] = page.writes();
    assert.deepEqual(call(write), ['PUT', '/api/admin/session-binding', { mode: 'ip' }]);
    assertCookieWrite(write);
    assert.equal(status.textContent, 'Saved preference: ip • Gateway active: none • restart required ⚠', 'the page shows the reloaded state');
    assert.equal(page.byId('session-binding-saved-value').textContent, 'ip');

    page.byId('session-binding-mode').value = 'strict';
    await page.click(page.byId('session-binding-save-btn'));
    assert.equal(status.textContent, 'Save failed: HTTP 500');
    assert.equal(page.requests.filter(r => r.url === '/api/admin/session-binding' && r.method === 'GET').length, 2, 'a failed save reloads nothing');

    // The gateway already enforces the saved mode: no restart banner.
    const applied = { saved: 'strict', gateway_active: 'strict', restart_required: false };
    page.routes['PUT /api/admin/session-binding'] = () => reply(200, applied);
    page.routes['GET /api/admin/session-binding'] = () => reply(200, applied);
    await page.click(page.byId('session-binding-save-btn'));
    assert.equal(status.textContent, 'Saved preference: strict • Gateway active: strict');
    assert.equal(page.byId('session-binding-restart-banner').style.display, 'none');
    assert.equal(page.byId('session-binding-mode').value, 'strict');
});

/* ------------------------------------------------------------------ */
/* WiFi security: the rogue-AP whitelist                               */
/* ------------------------------------------------------------------ */

test('AP whitelist: entries render as text; removing one needs confirmation and sends one encoded DELETE', async () => {
    let whitelist = [{ id: 'wl/../1?x', bssid: MARKUP, ssid: MARKUP, notes: MARKUP, added_at: '2026-11-01T00:00:00Z' }];
    let refuse = true;
    const page = await adminPage({
        routes: {
            'GET /api/admin/wifi-whitelist': () => reply(200, { whitelist }),
            'DELETE /api/admin/wifi-whitelist/wl%2F..%2F1%3Fx': () => {
                if (refuse) return reply(409, { detail: MARKUP });
                whitelist = [];
                return reply(204);
            },
        },
    });
    await page.tab('wifi-security');
    const tbody = page.byId('admin-whitelist-tbody');
    const shown = () => ({ empty: page.byId('admin-whitelist-empty').style.display, table: page.byId('admin-whitelist-table').style.display });
    assertInert(tbody, 'AP whitelist');
    for (const label of ['BSSID', 'SSID', 'Notes']) assert.equal(cell(tbody, label).textContent, MARKUP, label);
    assert.deepEqual(shown(), { empty: 'none', table: '' });

    const remove = () => page.click(tbody.querySelector('[data-wl-delete]'));
    await remove();
    assert.match(page.modal().textContent, /eligible to trigger rogue-AP detections again/);
    await page.click(page.button('Cancel'));
    await remove();
    await page.key('Escape');
    assert.deepEqual(page.writes(), []);

    await remove();
    await page.click(page.button('Remove'));
    assert.equal(tbody.querySelectorAll('tr').length, 1, 'a refused removal keeps the entry');
    refuse = false;
    await remove();
    await page.click(page.button('Remove'));
    assert.equal(tbody.innerHTML, '');
    assert.deepEqual(shown(), { empty: '', table: 'none' }, 'removing the last AP shows the empty state');
    const writes = page.writes();
    assert.deepEqual(writes.map(call), [
        ['DELETE', '/api/admin/wifi-whitelist/wl%2F..%2F1%3Fx', undefined],
        ['DELETE', '/api/admin/wifi-whitelist/wl%2F..%2F1%3Fx', undefined],
    ]);
    writes.forEach(w => assertCookieWrite(w, { json: false }));
    assert.deepEqual(page.toasts(), [
        { text: 'Failed to remove AP: ' + MARKUP, type: 'error', markup: 0 },
        { text: 'AP removed from whitelist', type: 'success', markup: 0 },
    ]);
});

test('adding an AP: a blank BSSID is refused before sending; the fields are sent trimmed with CSRF', async () => {
    const whitelist = [];
    let refuse = false;
    const page = await adminPage({
        routes: {
            'GET /api/admin/wifi-whitelist': () => reply(200, { whitelist }),
            'POST /api/admin/wifi-whitelist': request => {
                if (refuse) return reply(422, { detail: MARKUP });
                whitelist.push({ id: 'wl_1', added_at: '2026-11-10T12:00:00Z', ...request.body });
                return reply(201, {});
            },
        },
    });
    await page.tab('wifi-security');
    const shown = () => ({ empty: page.byId('admin-whitelist-empty').style.display, table: page.byId('admin-whitelist-table').style.display });
    assert.deepEqual(shown(), { empty: '', table: 'none' });
    const form = page.byId('admin-ap-form'), bssid = page.byId('ap-bssid-input');
    bssid.value = 'left over';
    await page.click(page.byId('admin-add-ap-btn'));
    assert.equal(form.style.display, '');
    assert.equal(bssid.value, '', 'the form opens empty');

    await page.input(bssid, '   ');
    await page.click(page.byId('ap-save-btn'));
    assert.deepEqual(page.writes(), []);

    bssid.value = ' AA:BB:CC:DD:EE:FF ';
    page.byId('ap-ssid-input').value = ' Corp ';
    page.byId('ap-notes-input').value = ' lobby ';
    await page.click(page.byId('ap-save-btn'));
    const [write] = page.writes();
    assert.deepEqual(call(write), ['POST', '/api/admin/wifi-whitelist', { bssid: 'AA:BB:CC:DD:EE:FF', ssid: 'Corp', notes: 'lobby' }]);
    assertCookieWrite(write);
    assert.equal(form.style.display, 'none');
    assert.deepEqual(shown(), { empty: 'none', table: '' }, 'the first AP replaces the empty state with the list');
    assert.equal(cell(page.byId('admin-whitelist-tbody'), 'BSSID').textContent, 'AA:BB:CC:DD:EE:FF');

    refuse = true;
    await page.click(page.byId('admin-add-ap-btn'));
    bssid.value = 'AA:BB:CC:DD:EE:FF';
    await page.click(page.byId('ap-save-btn'));
    assert.equal(form.style.display, '', 'a refused AP keeps the form open');
    assert.deepEqual(page.toasts(), [
        { text: 'BSSID is required.', type: 'error', markup: 0 },
        { text: 'AP added to whitelist', type: 'success', markup: 0 },
        { text: 'Failed to add AP to whitelist: ' + MARKUP, type: 'error', markup: 0 },
    ]);
    await page.click(page.byId('ap-cancel-btn'));
    assert.equal(form.style.display, 'none');
});

/* ------------------------------------------------------------------ */
/* Training, protocol and scorer-weight panels (admin.html's own       */
/* training.js, protocol_admin.js and scorer_weights.js)               */
/* ------------------------------------------------------------------ */

test('training runs: reported run fields render as text', async () => {
    const run = { run_id: 'run-1', status: 'active', dir: MARKUP, gpu: MARKUP, current_epoch: MARKUP, total_epochs: MARKUP,
        lr: MARKUP, batch_size: MARKUP, gamma: MARKUP, start_time: MARKUP, best_val_acc: 0.7 };
    const page = await adminPage({ scripts: PAGE_SCRIPTS, routes: { 'GET /api/training/runs': () => reply(200, [run]) } });
    await page.advance(100);   // training.js starts its panel 100 ms after DOMContentLoaded
    const list = page.byId('training-runs-list');
    assertInert(list, 'training runs');
    assert.equal(list.querySelector('[data-run-id]').getAttribute('data-run-id'), 'run-1');
    assert.equal(list.querySelector('strong').textContent, MARKUP);
    assert.deepEqual(list.querySelectorAll('.training-run-meta span').map(span => span.textContent), [
        'GPU: ' + MARKUP, 'Epoch: ' + MARKUP + '/' + MARKUP, 'Best: 70.0%', 'LR: ' + MARKUP, 'Batch: ' + MARKUP,
        'Gamma: ' + MARKUP, MARKUP]);
});

test('protocol toggles: a protocol the server names renders as text and is saved under that name', async () => {
    const saved = [];
    const page = await adminPage({
        scripts: PAGE_SCRIPTS,
        routes: {
            'GET /api/training/runs': () => reply(200, []),
            'GET /api/admin/protocols': () => reply(200, { protocols: { [MARKUP]: { enabled: true }, adsb: { enabled: false } } }),
            'PUT /api/admin/protocols': request => { saved.push(request.body); return reply(200, { status: 'ok' }); },
        },
    });
    await page.tab('protocols');
    const toggles = page.byId('protocol-toggles');
    assertInert(toggles, 'protocol toggles');
    const boxes = toggles.querySelectorAll('input[data-proto]');
    assert.deepEqual(boxes.map(box => [box.getAttribute('data-proto'), box.checked]), [[MARKUP, true], ['adsb', false]]);
    assert.deepEqual(boxes.map(box => box.parentNode.parentNode.textContent.trim()), [MARKUP, 'ADS-B']);
    await page.click(page.byId('save-protocols'));
    assert.deepEqual(saved, [{ [MARKUP]: true, adsb: false }]);
});

test('scorer weights: a weight the server names keeps its key, and a failed load is shown as text', async () => {
    let load = () => reply(200, { config: { rf_dimension_weights: { [MARKUP]: 0.2, novel_class: 0.1 } } });
    const saved = [];
    const page = await adminPage({
        scripts: PAGE_SCRIPTS,
        routes: {
            'GET /api/training/runs': () => reply(200, []),
            'GET /api/admin/detection-config': () => load(),
            'PUT /api/admin/detection-config': request => { saved.push(request.body); return reply(200, {}); },
        },
    });
    const container = page.byId('scorer-weights-container');
    await page.tab('scorer');
    await page.advance(100);   // the tab loads the weights 100 ms after it opens
    assertInert(container, 'scorer weights');
    assert.deepEqual(container.querySelectorAll('input').map(input => [input.getAttribute('data-key'), input.value]),
        [[MARKUP, '0.2'], [MARKUP, '0.2'], ['novel_class', '0.1'], ['novel_class', '0.1']]);
    assert.deepEqual(container.querySelectorAll('label').map(label => label.textContent), [MARKUP, 'Novel Class']);
    await page.click(page.byId('scorer-save-btn'));
    assert.deepEqual(saved, [{ rf_dimension_weights: { [MARKUP]: 0.2, novel_class: 0.1 } }]);

    // A request that fails before any reply rejects with the browser's message.
    load = () => { throw new TypeError(MARKUP); };
    await page.tab('scorer');
    await page.advance(100);
    assertInert(container, 'scorer weights failure');
    assert.equal(container.textContent, 'Failed to load: ' + MARKUP);
});

/* ------------------------------------------------------------------ */
/* Crypto keys (crypto_admin.js)                                       */
/* ------------------------------------------------------------------ */

const CRYPTO_KEY = { key_id: '6f1c0f5e-1d1a-4c55-9a43-3c8f7e1b2a90', protocol: 'DMR', label: 'site key', algorithm: 'AES-256-CTR', source: 'manual', key_len: 32, created_at: '2026-11-01T00:00:00Z' };

test('crypto keys: listed only when the tab opens; store labels render as text; revoke ids round-trip', async () => {
    const page = await adminPage({
        routes: {
            'GET /api/crypto/keys': () => reply(200, { keys: [
                { ...CRYPTO_KEY, key_id: ATTR_MARKUP, protocol: MARKUP, label: MARKUP, algorithm: MARKUP, source: MARKUP, key_len: MARKUP },
            ] }),
        },
    });
    assert.ok(!page.requests.some(r => r.url === '/api/crypto/keys'), 'nothing is listed before the tab opens');
    await page.tab('crypto');
    assert.equal(page.requests.filter(r => r.url === '/api/crypto/keys').length, 1);
    const tbody = page.byId('crypto-keys-tbody');
    assertInert(tbody, 'crypto key list');
    const cells = tbody.querySelectorAll('td').map(td => td.textContent);
    assert.deepEqual(cells.slice(0, 5), [MARKUP, MARKUP, MARKUP, MARKUP, MARKUP + ' bytes']);
    assert.equal(tbody.querySelector('[data-revoke]').getAttribute('data-revoke'), ATTR_MARKUP);
    assert.equal(page.byId('crypto-keys-empty').style.display, 'none');

    await page.tab('keys');
    assert.equal(page.requests.filter(r => r.url === '/api/crypto/keys').length, 1, 'leaving the tab does not reload');
});

test('crypto keys: an emptied store shows the empty state; a failed listing shows its error as text', async () => {
    let keys = [CRYPTO_KEY], fail = false;
    const page = await adminPage({
        routes: { 'GET /api/crypto/keys': () => { if (fail) throw new TypeError(MARKUP); return reply(200, keys); } },
    });
    const empty = page.byId('crypto-keys-empty');
    await page.tab('crypto');
    assert.equal(empty.style.display, 'none');
    keys = [];
    await page.tab('keys');
    await page.tab('crypto');
    assert.equal(page.byId('crypto-keys-tbody').innerHTML, '');
    assert.equal(empty.style.display, '', 'an empty store shows the empty state again');
    fail = true;
    await page.tab('keys');
    await page.tab('crypto');
    const tbody = page.byId('crypto-keys-tbody');
    assertInert(tbody, 'crypto key error');
    assert.equal(tbody.textContent, 'Error: ' + MARKUP);
    assert.equal(empty.style.display, 'none', 'a failed listing is not shown as an empty store');
});

test('crypto keys: a refused listing shows the server reason; a body without one shows the status', async () => {
    let answer = reply(503, { detail: 'key store locked' });
    const page = await adminPage({ routes: { 'GET /api/crypto/keys': () => answer } });
    await page.tab('crypto');
    assert.equal(page.byId('crypto-keys-tbody').textContent, 'Error: key store locked');
    answer = reply(502, '<html>Bad gateway</html>');
    await page.tab('keys');
    await page.tab('crypto');
    assert.equal(page.byId('crypto-keys-tbody').textContent, 'Error: HTTP 502');
});

test('revoking a crypto key needs confirmation, sends one encoded DELETE with CSRF, and reloads', async () => {
    let answer = false;
    const id = 'a/../b?c';
    const page = await adminPage({
        confirmAnswer: () => answer,
        routes: {
            'GET /api/crypto/keys': () => reply(200, [{ ...CRYPTO_KEY, key_id: id }]),
            'DELETE /api/crypto/keys/a%2F..%2Fb%3Fc': () => reply(200, { ok: true }),
        },
    });
    await page.tab('crypto');
    await page.click(page.byId('crypto-keys-tbody').querySelector('[data-revoke]'));
    assert.deepEqual(page.confirms, ['Revoke crypto key ' + id + '? This cannot be undone.']);
    assert.deepEqual(page.writes(), []);
    answer = true;
    await page.click(page.byId('crypto-keys-tbody').querySelector('[data-revoke]'));
    const [write] = page.writes();
    assert.deepEqual(call(write), ['DELETE', '/api/crypto/keys/a%2F..%2Fb%3Fc', undefined]);
    assertCookieWrite(write, { json: false });
    assert.equal(page.requests.filter(r => r.url === '/api/crypto/keys').length, 2);
    assert.deepEqual(page.alerts, []);
});

test('a refused crypto key revocation alerts', async () => {
    const page = await adminPage({
        routes: { 'GET /api/crypto/keys': () => reply(200, [CRYPTO_KEY]), ['DELETE /api/crypto/keys/' + CRYPTO_KEY.key_id]: () => reply(404, { detail: 'gone' }) },
    });
    await page.tab('crypto');
    await page.click(page.byId('crypto-keys-tbody').querySelector('[data-revoke]'));
    assert.equal(page.alerts.length, 1);
    assert.match(page.alerts[0], /^Error revoking key: /);
    assert.equal(page.alerts[0], 'Error revoking key: gone', 'the server reason is shown');
});

for (const [name, keyName, hex, message] of [
    ['a missing name', '  ', '00ff', 'Key name is required'],
    ['missing key material', 'site', '   ', 'Key hex is required'],
    ['non-hex key material', 'site', '00zz', 'Invalid hex value'],
    ['key material with punctuation', 'site', '00:ff', 'Invalid hex value'],
]) {
    test('crypto key import refuses ' + name + ' before sending', async () => {
        const page = await adminPage();
        await page.tab('crypto');
        page.byId('crypto-import-name').value = keyName;
        page.byId('crypto-import-hex').value = hex;
        await page.click(page.byId('crypto-import-btn'));
        assert.deepEqual(page.alerts, [message]);
        assert.deepEqual(page.writes(), []);
    });
}

test('crypto key import sends normalised key material with CSRF and clears it from the form', async () => {
    const page = await adminPage({ routes: { 'POST /api/crypto/keys': () => reply(201, { key_id: MARKUP }) } });
    await page.tab('crypto');
    page.byId('crypto-import-protocol').value = 'DMR';
    page.byId('crypto-import-algorithm').value = 'AES-256-CTR';
    page.byId('crypto-import-name').value = '  site key ';
    page.byId('crypto-import-hex').value = ' 00 11\taa BB\n';
    await page.click(page.byId('crypto-import-btn'));
    const [write] = page.writes();
    assert.deepEqual(call(write), ['POST', '/api/crypto/keys', { protocol: 'DMR', key_name: 'site key', raw_key_hex: '0011aaBB', algorithm: 'AES-256-CTR' }]);
    assertCookieWrite(write);
    const result = page.byId('crypto-import-result');
    assert.equal(result.textContent, 'Key imported: ' + MARKUP);
    assert.equal(result.children.length, 0);
    assert.equal(page.byId('crypto-import-hex').value, '', 'key material is not left in the form');
    assert.equal(page.byId('crypto-import-name').value, '');
    assert.equal(page.requests.filter(r => r.url === '/api/crypto/keys' && r.method === 'GET').length, 2);
});

test('a refused crypto key import keeps the form and shows an error as text', async () => {
    const page = await adminPage({ routes: { 'POST /api/crypto/keys': () => reply(422, { detail: MARKUP }) } });
    await page.tab('crypto');
    page.byId('crypto-import-name').value = 'site';
    page.byId('crypto-import-hex').value = '00ff';
    await page.click(page.byId('crypto-import-btn'));
    const result = page.byId('crypto-import-result');
    assert.match(result.textContent, /^Error: /);
    assert.equal(result.children.length, 0);
    assert.equal(page.byId('crypto-import-hex').value, '00ff');
});

test('a refused crypto key import shows the server reason', async () => {
    const page = await adminPage({ routes: { 'POST /api/crypto/keys': () => reply(422, { detail: 'raw_key_hex must be 16 or 32 bytes' }) } });
    await page.tab('crypto');
    page.byId('crypto-import-name').value = 'site';
    page.byId('crypto-import-hex').value = '00ff';
    await page.click(page.byId('crypto-import-btn'));
    assert.equal(page.byId('crypto-import-result').textContent, 'Error: raw_key_hex must be 16 or 32 bytes');
});

for (const [name, payload, message] of [['a missing payload', '  ', 'Payload hex is required'], ['a non-hex payload', 'xyz', 'Invalid hex value']]) {
    test('manual decrypt refuses ' + name + ' before sending', async () => {
        const page = await adminPage();
        await page.tab('crypto');
        page.byId('crypto-decrypt-payload').value = payload;
        await page.click(page.byId('crypto-decrypt-btn'));
        assert.deepEqual(page.alerts, [message]);
        assert.deepEqual(page.writes(), []);
    });
}

test('manual decrypt sends the payload and optional key id with CSRF; results and errors are text', async () => {
    const answers = [
        reply(200, { success: false, error: MARKUP }),
        reply(200, { success: true, plaintext_hex: MARKUP, key_id: MARKUP, algorithm: MARKUP, confidence: 0.875 }),
        reply(500, { detail: 'boom' }),
    ];
    const page = await adminPage({ routes: { 'POST /api/crypto/decrypt': () => answers.shift() } });
    await page.tab('crypto');
    page.byId('crypto-decrypt-protocol').value = 'P25';
    page.byId('crypto-decrypt-payload').value = 'de ad be ef';
    const output = page.byId('crypto-decrypt-output');
    await page.click(page.byId('crypto-decrypt-btn'));
    assert.equal(output.textContent, 'Failed: ' + MARKUP + '\n');
    page.byId('crypto-decrypt-key-id').value = ' ' + CRYPTO_KEY.key_id + ' ';
    await page.click(page.byId('crypto-decrypt-btn'));
    assert.equal(output.textContent, 'Plaintext (hex): ' + MARKUP + '\nKey used: ' + MARKUP + '\nAlgorithm: ' + MARKUP + '\nConfidence: 87.5%\n');
    await page.click(page.byId('crypto-decrypt-btn'));
    assert.match(output.textContent, /^Error: /);
    assert.equal(output.children.length, 0);
    assert.equal(page.byId('crypto-decrypt-result').style.display, '');

    const writes = page.writes();
    assert.deepEqual(writes.map(call), [
        ['POST', '/api/crypto/decrypt', { protocol: 'P25', payload_hex: 'deadbeef' }],
        ['POST', '/api/crypto/decrypt', { protocol: 'P25', payload_hex: 'deadbeef', key_id: CRYPTO_KEY.key_id }],
        ['POST', '/api/crypto/decrypt', { protocol: 'P25', payload_hex: 'deadbeef', key_id: CRYPTO_KEY.key_id }],
    ]);
    writes.forEach(w => assertCookieWrite(w));
});

test('crypto keys: sparse records, bodiless replies and unexpected decrypt answers are shown as text', async () => {
    const sparse = { protocol: 'DMR', label: 'site', algorithm: 'AES-256-CTR' };
    const listings = [{ keys: [{ ...sparse, key_id: 'k1' }, { ...sparse, key_id: 'k2' }] }, { keys: [{ ...sparse, key_id: 'k2' }] }, {}];
    const decrypts = [reply(200, { success: false }), reply(200, { note: MARKUP })];
    const page = await adminPage({
        routes: {
            'GET /api/crypto/keys': () => reply(200, listings.length > 1 ? listings.shift() : listings[0]),
            'DELETE /api/crypto/keys/k1': () => reply(204),
            'DELETE /api/crypto/keys/k2': () => new Response(null, { status: 200 }),
            'POST /api/crypto/keys': () => reply(201, 'created'),
            'POST /api/crypto/decrypt': () => decrypts.shift(),
        },
    });
    await page.tab('crypto');
    const tbody = page.byId('crypto-keys-tbody');
    assert.deepEqual(tbody.querySelector('tr').querySelectorAll('td').slice(0, 5).map(td => td.textContent),
        ['DMR', 'site', 'AES-256-CTR', 'manual', ' bytes']);

    await page.click(tbody.querySelector('[data-revoke="k1"]'));
    assert.deepEqual(tbody.querySelectorAll('[data-revoke]').map(b => b.getAttribute('data-revoke')), ['k2'], 'a 204 reloads the list');
    await page.click(tbody.querySelector('[data-revoke="k2"]'));
    assert.equal(tbody.innerHTML, '', 'an empty reply without a body reloads the list too');
    assert.equal(page.byId('crypto-keys-empty').style.display, '', 'a store answering without `keys` is empty');
    assert.deepEqual(page.alerts, []);

    page.byId('crypto-import-name').value = 'site';
    page.byId('crypto-import-hex').value = '00ff';
    await page.click(page.byId('crypto-import-btn'));
    const result = page.byId('crypto-import-result');
    assert.equal(result.textContent, 'Key imported: OK');
    assert.equal(result.style.display, '');
    await page.advance(30_000);
    assert.equal(result.style.display, 'none', 'the import notice goes away');

    page.byId('crypto-decrypt-payload').value = 'dead';
    const output = page.byId('crypto-decrypt-output');
    await page.click(page.byId('crypto-decrypt-btn'));
    assert.equal(output.textContent, 'Failed: unknown\n');
    await page.click(page.byId('crypto-decrypt-btn'));
    assert.equal(output.textContent, JSON.stringify({ note: MARKUP }, null, 2));
    assert.equal(output.children.length, 0);
    assert.deepEqual(page.writes().map(r => r.method + ' ' + r.url), [
        'DELETE /api/crypto/keys/k1', 'DELETE /api/crypto/keys/k2', 'POST /api/crypto/keys', 'POST /api/crypto/decrypt', 'POST /api/crypto/decrypt',
    ]);
});
