/* Shipped admin controller: visible feedback and mutation failure recovery. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const filename = path.resolve(__dirname, '../../../src/sigrift/bridge/static/admin.js');
const settle = () => new Promise(resolve => setImmediate(resolve));

class Element {
    constructor() { this.children = []; this.attributes = {}; this.style = {}; this.events = {}; this.disabled = false; this.classList = { add: value => { this.className += ' ' + value; } }; }
    appendChild(child) { this.children.push(child); child.parentNode = this; return child; }
    removeChild(child) { this.children.splice(this.children.indexOf(child), 1); child.parentNode = null; }
    get firstChild() { return this.children[0]; }
    get innerHTML() { return this.html || this.children.map(child => child.textContent.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')).join(''); }
    set innerHTML(value) { this.html = value; }
    setAttribute(name, value) { this.attributes[name] = value; }
    getAttribute(name) { return this.attributes[name]; }
    addEventListener(name, fn) { this.events[name] = fn; }
    click() { this.events.click.call(this); }
}

function fixture() {
    const container = new Element(), toggle = new Element(), table = new Element();
    const timers = [], logs = [], requests = [];
    toggle.setAttribute('data-wh-toggle', 'synthetic/id');
    toggle.setAttribute('data-wh-enabled', '1');
    table.querySelectorAll = selector => selector === '[data-wh-toggle]' ? [toggle] : [];
    const context = { console: { log: (...args) => logs.push(args), error: (...args) => logs.push(args) },
        document: { addEventListener() {}, createElement: () => new Element(), createTextNode: textContent => ({ textContent }),
            getElementById: id => ({ 'toast-container': container, 'admin-webhooks-tbody': table })[id] || null },
        window: {}, setTimeout: fn => timers.push(fn),
    };
    vm.runInNewContext(fs.readFileSync(filename, 'utf8'), context, { filename });
    const panel = Object.create(context.AdminPanel.prototype);
    let loads = 0;
    panel._loadNotifications = () => loads++;
    panel.apiFetch = async (url, options) => { requests.push({ url, options }); return {}; };
    panel._renderWebhooks([{ id: 'synthetic/id', name: 'Synthetic endpoint', enabled: true }]);
    return { context, container, toggle, timers, logs, panel, requests, loads: () => loads };
}

test('standalone admin errors are visible, accessible and literal text', () => {
    const f = fixture(), message = '<img src=x onerror=alert(1)> &quot;';
    f.context.notify(message, 'error');
    assert.equal(f.container.children.length, 1);
    assert.equal(f.container.firstChild.textContent, message);
    assert.equal(f.container.firstChild.getAttribute('role'), 'alert');
    assert.match(f.container.firstChild.className, /toast-error/);
    assert.equal(f.logs.length, 0);
});

test('ordinary feedback uses a status announcement and expires', () => {
    const f = fixture(); f.context.notify('Saved');
    assert.equal(f.container.firstChild.getAttribute('role'), 'status');
    assert.match(f.container.firstChild.className, /toast-info/);
    f.timers.shift()(); assert.match(f.container.firstChild.className, /toast-out/);
    f.timers.shift()(); assert.equal(f.container.children.length, 0);
});

test('bounded feedback safely expires an already removed oldest message', () => {
    const f = fixture(); for (let i = 0; i < 7; i++) f.context.notify(String(i), 'warning');
    assert.equal(f.container.children.length, 5);
    assert.equal(f.container.firstChild.textContent, '2');
    while (f.timers.length) f.timers.shift()();
    assert.equal(f.container.children.length, 0);
});

test('embedded dashboard feedback delegates once', () => {
    const f = fixture(), calls = []; f.context.window.showToast = (...args) => calls.push(args);
    f.context.notify('Saved');
    assert.deepEqual(calls, [['Saved', 'info']]); assert.equal(f.container.children.length, 0);
});

test('missing toast region preserves the console diagnostic fallback', () => {
    const f = fixture(); f.context.document.getElementById = () => null;
    f.context.notify('Failure', 'error'); f.context.notify('Information');
    assert.deepEqual(f.logs, [['Failure'], ['Information']]);
});

for (const failure of [{ detail: 'Configuration could not be saved' }, new Error('Connection lost'), {}]) {
    test('failed toggle preserves the visible state and exposes an actionable retry: ' + JSON.stringify(failure), async () => {
        const f = fixture(); f.panel.apiFetch = async (url, options) => { f.requests.push({ url, options }); throw failure; };
        f.toggle.click(); await settle();
        assert.equal(f.loads(), 0); assert.equal(f.toggle.getAttribute('data-wh-enabled'), '1');
        assert.equal(f.toggle.disabled, false);
        assert.equal(f.container.firstChild.textContent, 'Failed to update webhook: ' + (failure.detail || failure.message || 'Unknown error'));
        assert.equal(f.requests.length, 1);
        f.panel.apiFetch = async (url, options) => { f.requests.push({ url, options }); return {}; };
        f.toggle.click(); await settle(); assert.equal(f.loads(), 1); assert.equal(f.requests.length, 2);
        assert.equal(f.requests[1].url, '/api/admin/webhooks/synthetic%2Fid');
        assert.equal(f.requests[1].options.body.enabled, false);
    });
}

test('pending toggle cannot dispatch a second mutation', async () => {
    const f = fixture(); let complete;
    f.panel.apiFetch = (url, options) => { f.requests.push({ url, options }); return new Promise(resolve => { complete = resolve; }); };
    f.toggle.click(); f.toggle.click(); assert.equal(f.requests.length, 1); assert.equal(f.toggle.disabled, true);
    complete({}); await settle(); assert.equal(f.loads(), 1); assert.equal(f.toggle.disabled, false);
});

test('failed notification load is visible without fabricating an empty list', async () => {
    const f = fixture(); f.panel._loadSyslog = () => {};
    let rendered = 0; f.panel._renderWebhooks = () => rendered++;
    f.panel.apiFetch = async () => { throw { detail: 'Configuration is unavailable' }; };
    f.context.AdminPanel.prototype._loadNotifications.call(f.panel); await settle();
    assert.equal(rendered, 0);
    assert.equal(f.container.firstChild.textContent, 'Failed to load webhooks: Configuration is unavailable');
});
