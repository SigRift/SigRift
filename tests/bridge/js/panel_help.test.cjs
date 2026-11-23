const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const root = path.resolve(__dirname, '../../..');
const filename = path.join(root, 'src/sigrift/bridge/static/panel_help.js');

class Element {
    constructor(tag = 'div') {
        this.tagName = tag; this.attrs = {}; this.children = []; this.handlers = {}; this.style = {};
        this.hidden = false; this.textContent = ''; this.rect = {left: 100, top: 40, bottom: 64, width: 24, height: 24};
    }
    setAttribute(key, value) { this.attrs[key] = value; }
    getAttribute(key) { return this.attrs[key] ?? null; }
    removeAttribute(key) { delete this.attrs[key]; }
    appendChild(child) { this.children.push(child); child.parent = this; }
    contains(target) { return target === this || this.children.some(child => child.contains(target)); }
    querySelector(selector) { return this.children.find(child => '.' + child.className === selector) || null; }
    addEventListener(type, handler) { (this.handlers[type] ||= []).push(handler); }
    getBoundingClientRect() { return this.rect; }
    emit(type, extra = {}) {
        const event = {target: this, stopped: false, prevented: false,
            stopPropagation() { this.stopped = true; }, preventDefault() { this.prevented = true; }, ...extra};
        for (let current = this; current; current = current.parent) {
            for (const handler of current.handlers[type] || []) handler(event);
            if (event.stopped) break;
        }
        return event;
    }
}
function page(readyState = 'loading') {
    const document = new Element('document'); document.body = new Element('body'); document.appendChild(document.body);
    document.readyState = readyState; document.activeElement = null;
    document.createElement = tag => new Element(tag);
    const headings = ['Edge Nodes', 'Anomalies'].map(label => {
        const heading = new Element('h2'); heading.setAttribute('data-help-label', label);
        heading.setAttribute('data-help', label === 'Edge Nodes' ? 'Online does not prove scanning.' : '<img src=x onerror=evil()> remains text');
        document.body.appendChild(heading); return heading;
    });
    document.querySelectorAll = () => headings;
    const timers = new Map(); let id = 0;
    const window = new Element('window'); window.innerWidth = 600; window.innerHeight = 400;
    window.setTimeout = callback => { timers.set(++id, callback); return id; };
    window.clearTimeout = id => timers.delete(id);
    vm.runInNewContext(fs.readFileSync(filename, 'utf8'), {document, window}, {filename});
    if (readyState === 'loading') document.emit('DOMContentLoaded');
    const controller = window.panelHelp, buttons = headings.map(h => h.children[0]);
    const focus = button => { document.activeElement?.emit('blur'); document.activeElement = button; button.emit('focus'); button.emit('focusin'); };
    return {document, window, headings, buttons, controller, focus, timers,
        tick() { const callbacks = [...timers.values()]; timers.clear(); callbacks.forEach(callback => callback()); }};
}

test('native labeled buttons describe focused heading and render text, never markup', () => {
    const p = page(); const b = p.buttons[1];
    assert.equal(b.tagName, 'button'); assert.equal(b.type, 'button');
    assert.equal(b.textContent, '', 'help must preserve the heading text used by freshness lookup');
    assert.equal(b.getAttribute('aria-label'), 'About Anomalies');
    assert.equal(p.controller.tip.hidden, true);
    p.focus(b);
    assert.equal(b.getAttribute('aria-describedby'), p.controller.tip.id);
    assert.equal(p.controller.tip.getAttribute('role'), 'tooltip');
    assert.equal(p.controller.tip.textContent, '<img src=x onerror=evil()> remains text');
    assert.equal(p.controller.tip.children.length, 0);
});

test('Escape dismisses without moving focus and removes stale description', () => {
    const p = page(); p.focus(p.buttons[0]);
    const event = p.document.emit('keydown', {key: 'Escape'});
    assert.equal(event.prevented, true); assert.equal(event.stopped, true);
    assert.equal(p.document.activeElement, p.buttons[0]);
    assert.equal(p.controller.tip.hidden, true);
    assert.equal(p.buttons[0].getAttribute('aria-describedby'), null);
    assert.equal(p.buttons[0].getAttribute('aria-expanded'), 'false');
    assert.equal(p.document.emit('keydown', {key: 'Escape'}).prevented, false);
});

test('tap pins, repeat tap closes and neither click collapses the parent header', () => {
    const p = page(); let collapsed = false;
    p.headings[0].addEventListener('click', () => { collapsed = !collapsed; });
    p.focus(p.buttons[0]); p.buttons[0].emit('click'); p.buttons[0].emit('pointerleave'); p.tick();
    assert.equal(p.controller.tip.hidden, false); assert.equal(collapsed, false);
    p.buttons[0].emit('click'); assert.equal(p.controller.tip.hidden, true); assert.equal(collapsed, false);
    for (const key of ['Enter', ' ']) assert.equal(p.buttons[0].emit('keydown', {key}).stopped, true);
    assert.equal(p.buttons[0].emit('keydown', {key: 'Tab'}).stopped, false);
});

test('hover remains readable across pointer travel into the tooltip then dismisses', () => {
    const p = page(); p.buttons[0].emit('pointerenter');
    p.buttons[0].emit('pointerleave'); assert.equal(p.controller.tip.hidden, false);
    p.controller.tip.emit('pointerenter'); p.tick(); assert.equal(p.controller.tip.hidden, false);
    p.controller.tip.emit('pointerleave'); p.tick(); assert.equal(p.controller.tip.hidden, true);
});

test('keyboard focus keeps help visible after hover leaves; blur hides it', () => {
    const p = page(); p.focus(p.buttons[0]); p.buttons[0].emit('pointerleave'); p.tick();
    assert.equal(p.controller.tip.hidden, false);
    p.buttons[0].emit('blur'); assert.equal(p.controller.tip.hidden, true);
});

test('outside pointer/focus dismisses while pointer inside the help does not', () => {
    const p = page(); p.buttons[0].emit('click');
    p.controller.tip.emit('pointerdown'); assert.equal(p.controller.tip.hidden, false);
    p.document.body.emit('pointerdown'); assert.equal(p.controller.tip.hidden, true);
    p.buttons[0].emit('click'); p.document.body.emit('focusin'); assert.equal(p.controller.tip.hidden, true);
});

test('moving between help buttons keeps exactly one description with the correct copy', () => {
    const p = page(); p.buttons[0].emit('pointerenter'); p.buttons[1].emit('pointerenter');
    assert.equal(p.buttons[0].getAttribute('aria-expanded'), 'false');
    assert.equal(p.buttons[1].getAttribute('aria-expanded'), 'true');
    assert.match(p.controller.tip.textContent, /remains text/);
});

test('tooltip stays inside viewport and hidden anchors close after layout changes', () => {
    const p = page('complete'); p.controller.tip.rect = {width: 250, height: 100};
    p.buttons[0].rect = {left: 590, top: 370, bottom: 394, width: 24, height: 24};
    p.buttons[0].emit('click');
    assert.equal(p.controller.tip.style.left, '342px'); assert.equal(p.controller.tip.style.top, '262px');
    p.window.innerWidth = 300; p.window.emit('resize'); assert.equal(p.controller.tip.style.left, '42px');
    p.buttons[0].rect.width = 0; p.window.emit('scroll'); assert.equal(p.controller.tip.hidden, true);
    p.window.emit('scroll'); // no active target is harmless
});

test('initialization is idempotent and incomplete empty headings add no control', () => {
    const p = page(); p.document.emit('DOMContentLoaded');
    assert.equal(p.headings[0].children.length, 1);
    p.controller.add(p.headings[0]); assert.equal(p.headings[0].children.length, 1);
    const empty = new Element(); p.controller.add(empty); assert.equal(empty.children.length, 0);
    empty.setAttribute('data-help', 'text'); p.controller.add(empty); assert.equal(empty.children.length, 0);
});

test('shipped dashboard/admin principal panels use authored accessible help with external assets', () => {
    for (const name of ['index', 'admin']) {
        const html = fs.readFileSync(path.join(root, `src/sigrift/bridge/templates/${name}.html`), 'utf8');
        assert.match(html, /path='panel_help\.js'/); assert.match(html, /path='panel_help\.css'/);
        assert.doesNotMatch(html, /class="help-tip"/);
        const headings = [...html.matchAll(/<h2\b([^>]*)class="card-title"([^>]*)>/g)];
        assert.ok(headings.length > 20);
        for (const heading of headings) assert.match(heading[1] + heading[2], /data-help-label=".+" data-help=".+"/);
        assert.doesNotMatch(html, /Immutable record of all|will not trigger 'new network' alerts/);
    }
});
