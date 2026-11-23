/* Shiny dashboard spectrum panel: a refused connect / disconnect is reported.
 *
 * Connecting to rtl_tcp and disconnecting it need an analyst key on the
 * server (a viewer key gets 403 "analyst role required").  The shipped
 * dashboard.js and spectrum.js run together in a stub DOM, as the page
 * loads them; the Connect and Disconnect buttons are clicked and the server
 * answers through a stubbed fetch.
 */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const parse5 = require('parse5');

const root = path.resolve(__dirname, '../../..');
const sources = ['dashboard.js', 'spectrum.js'].map(name => path.join(root, 'src/sigrift/lib/shiny/static', name));
const settle = async () => { for (let i = 0; i < 5; i++) await new Promise(resolve => setImmediate(resolve)); };

function nodes(node, tag) {
    return [...(node.tagName === tag ? [node] : []), ...(node.childNodes || []).flatMap(child => nodes(child, tag))];
}
function text(node) {
    return node.nodeName === '#text' ? node.value : (node.childNodes || []).map(text).join('');
}

function element(value = '') {
    let html = '', tree = null;
    const events = {};
    return {
        value, textContent: '', style: {}, disabled: false,
        get innerHTML() { return html; },
        set innerHTML(v) { html = v; tree = parse5.parseFragment(v); },
        get text() { return tree ? text(tree) : ''; },
        get tags() { return tree ? nodes(tree, 'b').length + nodes(tree, 'img').length : 0; },
        addEventListener(type, fn) { (events[type] ||= []).push(fn); },
        click() { for (const fn of events.click || []) fn.call(this, {}); },
    };
}

function response(status, body) {
    return {
        status, ok: status >= 200 && status < 300,
        headers: {get: name => (name.toLowerCase() === 'content-type' ? 'application/json' : null)},
        json: () => Promise.resolve(body),
    };
}

function fixture() {
    const els = {
        'spec-host': element('10.0.0.5'), 'spec-port': element('1234'), 'spec-freq': element('868'),
        'spec-gain': element('20'), 'spec-connect': element(), 'spec-disconnect': element(),
        'spectrum-badge': element(), 'modal-title': element(), 'modal-body': element(), 'modal-overlay': element(),
    };
    els['modal-overlay'].style.display = 'none';
    const requests = [], sockets = [];
    let reply = () => response(200, {});
    const context = {
        console,
        FormData: class FormData {},
        sessionStorage: {getItem: () => 'viewer-key', setItem() {}},
        location: {protocol: 'https:', host: 'dash.test'},
        WebSocket: class { constructor(url, protocols) { this.url = url; this.protocols = protocols; this.readyState = 0; sockets.push(this); } close() {} },
        setTimeout() {},
        document: {
            addEventListener() {},
            getElementById: id => els[id] || null,
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
        fetch: (url, options) => {
            requests.push({url, method: options.method || 'GET', headers: options.headers, body: options.body});
            return Promise.resolve(reply(url, options));
        },
    };
    vm.createContext(context);
    for (const source of sources) vm.runInContext(fs.readFileSync(source, 'utf8'), context, {filename: source});
    const db = Object.create(context.ShinyDashboard.prototype);
    db.apiKey = 'viewer-key';
    const viewer = new context.SpectrumViewer(db);
    return {db, viewer, els, requests, sockets,
        answer(fn) { reply = fn; },
        modal: () => (els['modal-overlay'].style.display === '' ? {title: els['modal-title'].textContent,
            text: els['modal-body'].text, tags: els['modal-body'].tags} : null)};
}

const DENIED = '<b>analyst role required</b>';

test('a refused connect is reported and leaves the viewer disconnected', async () => {
    const f = fixture();
    f.answer(() => response(403, {detail: DENIED}));
    f.els['spec-connect'].click(); await settle();
    assert.deepEqual(f.requests.map(r => [r.url, r.method]), [['/api/spectrum/connect', 'POST']]);
    assert.equal(f.requests[0].headers['X-API-Key'], 'viewer-key');
    assert.deepEqual(JSON.parse(f.requests[0].body),
        {host: '10.0.0.5', port: 1234, center_freq_hz: 868e6, gain_db: 20, sample_rate_hz: 2048000});
    assert.equal(f.els['spectrum-badge'].textContent, 'Error');
    assert.equal(f.viewer.connected, false);
    assert.deepEqual(f.sockets, []);
    const modal = f.modal();
    assert.ok(modal, 'no notice for a 403');
    assert.equal(modal.title, 'Not permitted');
    assert.match(modal.text, /This API key cannot connect to rtl_tcp: <b>analyst role required<\/b>\./);
    assert.match(modal.text, /Viewer keys are read-only/);
    assert.equal(modal.tags, 0);
});

test('a refused disconnect is reported and keeps the stream', async () => {
    const f = fixture();
    f.viewer.connected = true;
    f.answer(() => response(403, {detail: DENIED}));
    f.els['spec-disconnect'].click(); await settle();
    assert.deepEqual(f.requests.map(r => [r.url, r.method]), [['/api/spectrum/disconnect', 'GET']]);
    assert.equal(f.viewer.connected, true);
    assert.match(f.modal().text, /This API key cannot disconnect from rtl_tcp: <b>analyst role required<\/b>\./);
});

test('other failures only mark the badge, and success connects and disconnects', async () => {
    for (const status of [422, 500, 502]) {
        const f = fixture();
        f.answer(() => response(status, {detail: 'x'}));
        f.els['spec-connect'].click(); await settle();
        assert.equal(f.els['spectrum-badge'].textContent, 'Error');
        f.els['spec-disconnect'].click(); await settle();
        assert.equal(f.requests.length, 2);
        assert.equal(f.modal(), null, `notice for a ${status}`);
    }

    const f = fixture();
    f.answer(url => response(200, url === '/api/spectrum/config'
        ? {center_freq_hz: 868e6, sample_rate_hz: 2048000, gain_db: 20, fft_size: 1024} : {status: 'ok'}));
    f.els['spec-connect'].click(); await settle();
    assert.equal(f.viewer.connected, true);
    assert.equal(f.els['spectrum-badge'].textContent, 'Connected');
    assert.deepEqual([f.els['spec-connect'].disabled, f.els['spec-disconnect'].disabled], [true, false]);
    // The key goes in the WebSocket subprotocol, never in the URL.
    assert.deepEqual(f.sockets.map(s => [s.url, [...s.protocols]]),
        [['wss://dash.test/api/spectrum/ws/spectrum', ['bridge-v1', 'viewer-key']]]);
    assert.equal(f.viewer.config.center_freq_hz, 868e6);
    f.els['spec-disconnect'].click(); await settle();
    assert.equal(f.viewer.connected, false);
    assert.equal(f.els['spectrum-badge'].textContent, 'Disconnected');
    assert.equal(f.viewer.ws, null);
    assert.equal(f.modal(), null);
});
