/* The admin console's shell (admin.js): tab deep links and keyboard focus
 * in its dialogs, in the admin_dom.cjs stub DOM. */
const assert = require('node:assert/strict');
const test = require('node:test');
const { adminPage, noUnexpectedConsoleErrors, reply, FakeEvent } = require('./admin_dom.cjs');

test.afterEach(noUnexpectedConsoleErrors);

const panelShown = (page, name) => page.byId('tab-' + name).style.display !== 'none';

test('a link to a tab opens that tab once signed in, and loads only that tab', async () => {
    const page = await adminPage({
        hash: '#audit',
        routes: { 'GET /api/admin/audit': () => reply(200, { entries: [] }), 'GET /api/admin/audit/filters': () => reply(200, {}) },
    });
    assert.ok(page.doc.querySelector('[data-tab="audit"]').classList.contains('active'));
    assert.ok(!page.doc.querySelector('[data-tab="keys"]').classList.contains('active'));
    assert.deepEqual([panelShown(page, 'audit'), panelShown(page, 'keys')], [true, false]);
    const urls = page.requests.map(r => r.url);
    assert.ok(urls.includes('/api/admin/audit?limit=50&offset=0'));
    assert.ok(!urls.includes('/api/admin/keys'), 'the API keys tab is not loaded behind the linked tab');
    // Opening another tab updates the link (a browser reads it back with its '#'; the stub keeps what was assigned).
    await page.tab('keys');
    assert.equal(page.context.location.hash.replace(/^#/, ''), 'keys');
});

test('a link to a tab the console does not have opens the API keys tab', async () => {
    const page = await adminPage({ hash: '#no-such-tab' });
    assert.ok(page.doc.querySelector('[data-tab="keys"]').classList.contains('active'));
    assert.ok(panelShown(page, 'keys'));
    assert.ok(page.requests.some(r => r.url === '/api/admin/keys'));
});

function tab(page, shiftKey = false) {
    const event = new FakeEvent('keydown', { key: 'Tab', shiftKey });
    page.doc.dispatchEvent(event);
    return event.defaultPrevented;
}

test('Tab and Shift+Tab keep the keyboard focus inside an open dialog', async () => {
    const page = await adminPage({ routes: { 'GET /api/admin/alerts': () => reply(200, []), 'GET /api/alerts/rules/conditions': () => reply(200, []) } });
    await page.tab('alerts');
    page.byId('admin-create-alert-btn').focus(); // a click focuses the button in a browser; the stub's click does not
    await page.click(page.byId('admin-create-alert-btn'));
    const modal = page.modal();
    const name = modal.querySelector('#admin-modal-alert-name'), severity = modal.querySelector('#admin-modal-alert-severity');
    const cancel = page.button('Cancel'), create = page.button('Create');
    assert.equal(create.disabled, true);
    assert.equal(page.doc.activeElement, name, 'the first field has focus');

    assert.equal(tab(page, true), true, 'Shift+Tab on the first control wraps');
    assert.equal(page.doc.activeElement, cancel, 'to the last enabled control (Create is disabled)');
    assert.equal(tab(page, true), false, 'Shift+Tab on the last control moves back as usual, not to the first');
    assert.equal(page.doc.activeElement, cancel);
    assert.equal(tab(page), true, 'Tab on the last control wraps');
    assert.equal(page.doc.activeElement, name);
    severity.focus();
    assert.equal(tab(page), false, 'between the ends the browser moves focus as usual');
    assert.equal(tab(page, true), false);
    assert.equal(page.doc.activeElement, severity);

    await page.input(name, 'Jammer');
    cancel.focus();
    assert.equal(tab(page), false, 'once Create is enabled, Cancel is no longer the last control');
    create.focus();
    assert.equal(tab(page), true);
    assert.equal(page.doc.activeElement, name);

    await page.key('Escape');
    assert.equal(page.modal(), null);
    assert.equal(tab(page), false, 'a closed dialog no longer holds the focus');
    assert.equal(page.doc.activeElement, page.byId('admin-create-alert-btn'), 'focus returns to the control that opened the dialog');
});

test('a confirmation dialog focuses its first button and keeps Tab between its buttons', async () => {
    const key = { key_id: 'key_a1', role: 'viewer', created_at: '2026-11-01T00:00:00Z', expired: false };
    const page = await adminPage({ routes: { 'GET /api/admin/keys': () => reply(200, [key]) } });
    const revoke = page.byId('keys-tbody').querySelector('[data-revoke]');
    revoke.focus();
    await page.click(revoke);
    const cancel = page.button('Cancel'), confirm = page.button('Revoke');
    assert.equal(page.doc.activeElement, cancel);
    assert.equal(tab(page), false);
    confirm.focus();
    assert.equal(tab(page), true);
    assert.equal(page.doc.activeElement, cancel);
    assert.equal(tab(page, true), true);
    assert.equal(page.doc.activeElement, confirm);
    assert.equal(tab(page, true), false, 'Shift+Tab from the last button goes back to the first as usual');
    assert.equal(page.doc.activeElement, confirm, 'the dialog leaves that move to the browser');
    await page.click(cancel);
    assert.equal(page.doc.activeElement, revoke);
    assert.deepEqual(page.writes(), []);
});
