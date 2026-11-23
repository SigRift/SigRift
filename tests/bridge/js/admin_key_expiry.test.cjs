/* Shipped admin key creation: the "Expires (days)" field never turns a typo into the default lifetime; blank asks for it. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const bridgeDir = path.resolve(__dirname, '../../../src/sigrift/bridge');
const filename = path.join(bridgeDir, 'static/admin.js');
const settle = () => new Promise(resolve => setImmediate(resolve));

/* The shipped field's attributes (type, min, max) as templates/admin.html declares them. */
const template = fs.readFileSync(path.join(bridgeDir, 'templates/admin.html'), 'utf8');
const expiresTag = /<input[^>]*id="new-key-expires"[^>]*>/.exec(template)[0];
const expiresAttributes = Object.fromEntries([...expiresTag.matchAll(/([\w-]+)="([^"]*)"/g)].map(m => m.slice(1)));

class Element {
    constructor(attributes = {}, value = '') {
        this.attributes = attributes; this.value = value; this.style = {}; this.innerHTML = ''; this.focused = 0;
    }
    getAttribute(name) { return name in this.attributes ? this.attributes[name] : null; }
    focus() { this.focused += 1; }
}

/* What esc() builds: a <div> holding one text node, serialised like the DOM does. */
class TextHolder {
    constructor() { this.text = ''; }
    appendChild(node) { this.text += node.textContent; return node; }
    get innerHTML() { return this.text.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;'); }
}

function fixture(expires, { badInput = false, attributes = expiresAttributes } = {}) {
    const requests = [], notices = [], reveals = [];
    const expiresEl = new Element(attributes, expires);
    expiresEl.validity = { badInput };
    const elements = {
        'new-key-desc': new Element({}, ' rooftop sensor '),
        'new-key-role': new Element({}, 'sensor'),
        'new-key-expires': expiresEl,
        'key-created-display': new Element(),
    };
    const context = {
        console,
        document: {
            addEventListener() {}, createElement: () => new TextHolder(), createTextNode: textContent => ({ textContent }),
            getElementById: id => elements[id] || null,
        },
        window: {}, setTimeout() {},
    };
    vm.runInNewContext(fs.readFileSync(filename, 'utf8'), context, { filename });
    context.notify = (message, type) => notices.push([message, type]);
    const panel = Object.create(context.AdminPanel.prototype);
    panel.apiFetch = async (url, options) => {
        requests.push(JSON.parse(JSON.stringify({ url, options })));
        return { key_id: 'key_new', raw_key: 'raw' };
    };
    panel._loadKeys = () => {};
    panel._showRawKeyReveal = options => reveals.push(options.keyId);
    return { panel, requests, notices, reveals, elements };
}

const refusal = 'Key not created: expiry must be a whole number of days from 1 to 3650, or blank for the default lifetime';

test('the shipped field allows the API range: 1 to 3650 days', () => {
    assert.deepEqual([expiresAttributes.type, expiresAttributes.min, expiresAttributes.max], ['number', '1', '3650']);
});

for (const [name, value, body] of [
    ['blank: the default lifetime (no expires_days sent)', '', { description: 'rooftop sensor', role: 'sensor' }],
    ['30 days', '30', { description: 'rooftop sensor', role: 'sensor', expires_days: 30 }],
    ['one day', '1', { description: 'rooftop sensor', role: 'sensor', expires_days: 1 }],
    ['the maximum', '3650', { description: 'rooftop sensor', role: 'sensor', expires_days: 3650 }],
]) {
    test('an expiry in range is sent: ' + name, async () => {
        const f = fixture(value);
        f.panel._createKey();
        await settle();
        assert.deepEqual(f.requests, [{ url: '/api/admin/keys', options: { method: 'POST', body } }]);
        assert.deepEqual(f.notices, []);
        assert.deepEqual(f.reveals, ['key_new']);
        assert.match(f.elements['key-created-display'].innerHTML, /Key created\./);
        assert.equal(f.elements['new-key-expires'].value, '');
    });
}

for (const [name, value, options] of [
    ['negative (a typo for 30)', '-30'],
    ['zero', '0'],
    ['minus one', '-1'],
    ['over the maximum', '3651'],
    ['far over the maximum', '5000'],
    ['fractional', '2.5'],
    ['exponent', '1e3'],
    ['text the number field could not parse', '', { badInput: true }],
]) {
    test('an expiry out of range sends nothing and says why: ' + name, async () => {
        const f = fixture(value, options);
        f.panel._createKey();
        await settle();
        assert.deepEqual(f.requests, []);
        assert.deepEqual(f.notices, [[refusal, 'error']]);
        assert.deepEqual(f.reveals, []);
        assert.equal(f.elements['key-created-display'].innerHTML, '');
        assert.equal(f.elements['new-key-expires'].focused, 1);
        assert.equal(f.elements['new-key-expires'].value, value, 'the typo stays in the field to correct');
    });
}

test('without a max on the field, only the lower bound is checked here (the API refuses the rest)', async () => {
    const { max, ...noMax } = expiresAttributes;
    assert.equal(max, '3650');
    const refused = fixture('0', { attributes: noMax });
    refused.panel._createKey();
    await settle();
    assert.deepEqual(refused.requests, []);
    assert.deepEqual(refused.notices, [['Key not created: expiry must be a whole number of days of at least 1, '
        + 'or blank for the default lifetime', 'error']]);
    const sent = fixture('5000', { attributes: noMax });
    sent.panel._createKey();
    await settle();
    assert.equal(sent.requests[0].options.body.expires_days, 5000);
});
