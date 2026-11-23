/* Shiny dashboard key panel: the shipped dashboard.js _renderKeys in a stub DOM. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const parse5 = require('parse5');

const root = path.resolve(__dirname, '../../..');
const source = path.join(root, 'src/sigrift/lib/shiny/static/dashboard.js');
const settle = () => new Promise(resolve => setImmediate(resolve));

function attributes(node) { return Object.fromEntries((node.attrs || []).map(attr => [attr.name, attr.value])); }
function nodes(node, tag) {
    return [...(node.tagName === tag ? [node] : []), ...(node.childNodes || []).flatMap(child => nodes(child, tag))];
}
function text(node) {
    return node.nodeName === '#text' ? node.value : (node.childNodes || []).map(text).join('');
}

function button(node) {
    const attrs = attributes(node), events = {};
    return {attrs, text: text(node), events,
        getAttribute: name => attrs[name], addEventListener(type, fn) { (events[type] ||= []).push(fn); },
        click() { for (const fn of events.click || []) fn.call(this, {}); }};
}

// keys-tbody parses what _renderKeys writes, so rows and buttons are read
// as a browser would build them, not by string matching.
function fixture({confirmed = true, table = true} = {}) {
    let html = '', rows = [], buttons = [];
    const tbody = {
        get innerHTML() { return html; },
        set innerHTML(value) {
            html = value;
            const parsed = parse5.parseFragment('<table><tbody>' + value + '</tbody></table>');
            buttons = [];
            rows = nodes(parsed, 'tr').map(tr => {
                const own = nodes(tr, 'button').map(button);
                buttons.push(...own);
                return {cells: nodes(tr, 'td').map(text), html: parse5.serialize(tr), buttons: own,
                    images: nodes(tr, 'img').length};
            });
        },
        querySelectorAll(selector) {
            const name = selector.replace(/^\[|\]$/g, '');
            return buttons.filter(b => Object.hasOwn(b.attrs, name));
        },
    };
    const confirms = [];
    const context = {
        console,
        document: {
            addEventListener() {},
            getElementById: id => (table && id === 'keys-tbody' ? tbody : null),
            // A browser's innerHTML of a text node escapes &, < and >.
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
        confirm: message => { confirms.push(message); return confirmed; },
    };
    vm.runInNewContext(fs.readFileSync(source, 'utf8'), context, {filename: source});
    const db = Object.create(context.ShinyDashboard.prototype), calls = [];
    let reloads = 0;
    db.apiFetch = (url, options) => { calls.push({url, method: options && options.method}); return Promise.resolve({raw_key: 'new', message: 'm'}); };
    db._loadKeys = () => { reloads++; };
    db._showKeyModal = () => {};
    return {db, context, calls, confirms, tbody, reloads: () => reloads,
        render(keys) { db._renderKeys(keys); return rows; },
        row: key_id => rows.find(r => r.cells[0] === key_id)};
}

function key(key_id, extra = {}) {
    return {key_id, description: 'd', created_at: '2026-01-01T00:00:00+00:00', expires_at: null, node_id: null, ...extra};
}

test('the master row offers rotation but never revocation', async () => {
    const f = fixture();
    f.render([key('master', {expired: false}), key('node-1', {node_id: 'edge-1', expired: false})]);
    const master = f.row('master'), node = f.row('node-1');
    assert.deepEqual(master.buttons.map(b => b.text), ['Rotate']);
    assert.equal(master.buttons[0].getAttribute('data-rotate-key'), 'master');
    assert.equal(master.html.includes('data-revoke-key'), false);
    assert.deepEqual(node.buttons.map(b => b.text), ['Rotate', 'Revoke']);
    assert.deepEqual(f.tbody.querySelectorAll('[data-revoke-key]').map(b => b.getAttribute('data-revoke-key')), ['node-1']);
    assert.equal(node.cells[4], 'edge-1');
    // The role each key holds (a server that lists none: a viewer).
    assert.deepEqual([master.cells[5], node.cells[5]], ['viewer', 'viewer']);

    master.buttons[0].click(); await settle();
    assert.deepEqual(f.calls, [{url: '/api/keys/master/rotate', method: 'PUT'}]);
    node.buttons[1].click(); await settle();
    assert.deepEqual(f.confirms, ['Revoke key node-1?']);
    assert.deepEqual(f.calls.at(-1), {url: '/api/keys/node-1', method: 'DELETE'});
    assert.equal(f.reloads(), 2);
});

test('a cancelled revocation sends nothing', () => {
    const f = fixture({confirmed: false});
    f.render([key('node-1')]);
    f.row('node-1').buttons[1].click();
    assert.equal(f.confirms.length, 1);
    assert.deepEqual(f.calls, []);
});

test('an expired key never reads as "Never", even when its expiry cannot be parsed', () => {
    const f = fixture(), fmt = f.context.fmtTime;
    const past = '2000-01-01T00:00:00+00:00', future = '2999-01-01T00:00:00+00:00';
    f.render([
        key('forever', {expired: false}),
        key('old-server'), // a server from before "expired" existed
        key('future', {expires_at: future, expired: false}),
        key('lapsed', {expires_at: past, expired: true}),
        // The server lists an unparseable stored expiry as null, and
        // rejects the key.
        key('garbled', {expires_at: null, expired: true}),
    ]);
    const expires = id => f.row(id).cells[3];
    assert.equal(expires('forever'), 'Never');
    assert.equal(expires('old-server'), 'Never');
    assert.equal(expires('future'), fmt(future));
    assert.notEqual(fmt(future), '--');
    assert.equal(expires('lapsed'), 'Expired ' + fmt(past));
    assert.equal(expires('garbled'), 'Expired (invalid date)');
});

test('stored strings render as text and an empty or missing table is handled', () => {
    const f = fixture();
    const [row] = f.render([key('k', {description: '<img src=x onerror=alert(1)>', created_at: null})]);
    assert.equal(row.cells[1], '<img src=x onerror=alert(1)>');
    assert.equal(row.images, 0);
    assert.equal(row.cells[2], '--');
    assert.equal(row.cells[4], '--');
    f.render([]);
    assert.match(f.tbody.innerHTML, /No keys/);
    assert.doesNotThrow(() => fixture({table: false}).db._renderKeys([key('master')]));
});

test('each key shows its role, as text', () => {
    const f = fixture();
    f.render([key('ops', {role: 'analyst'}), key('lead', {role: 'admin'}), key('odd', {role: '<b>invalid:x</b>'})]);
    assert.deepEqual(['ops', 'lead', 'odd'].map(id => f.row(id).cells[5]), ['analyst', 'admin', '<b>invalid:x</b>']);
    assert.equal(f.row('odd').html.includes('<b>'), false);
    f.render([]);
    assert.match(f.tbody.innerHTML, /colspan="7"/);
});
