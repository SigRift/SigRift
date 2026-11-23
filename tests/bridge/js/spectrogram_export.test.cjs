const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const root = path.resolve(__dirname, '../../..');
const filename = path.join(root, 'src/sigrift/bridge/static/spectrogram_viewer.js');

class Element {
    constructor(id) { this.id = id; this.handlers = {}; this.attrs = {}; this.style = {}; this.value = ''; }
    addEventListener(type, handler) { (this.handlers[type] ||= []).push(handler); }
    getAttribute(name) { return this.attrs[name] ?? null; }
    setAttribute(name, value) { this.attrs[name] = String(value); }
    removeAttribute(name) { delete this.attrs[name]; }
    click() { for (const handler of this.handlers.click || []) handler.call(this, {target: this}); }
}

/* The Deep-Dive spectrogram card of the dashboard, and the dashboard class
 * whose tab setup initialises it. */
function dashboard() {
    const ids = ['spectrogram-card', 'spectrogram-canvas', 'sg-export-png', 'sg-colormap', 'sg-nfft', 'sg-window'];
    const elements = Object.fromEntries(ids.map(id => [id, new Element(id)]));
    const canvas = elements['spectrogram-canvas'];
    canvas.width = 900; canvas.height = 400;
    canvas.getContext = () => ({});
    canvas.toDataURL = type => `data:${type};base64,UE5H`;
    const links = [];
    const document = {
        getElementById: id => elements[id] || null,
        createElement: tag => {
            const link = {tag, clicked: 0, click() { this.clicked++; }};
            links.push(link); return link;
        },
        documentElement: {},
    };
    function BridgeDashboard() {}
    BridgeDashboard.prototype._initTabs = function() { this.tabsReady = true; };
    const context = {document, BridgeDashboard, window: {}, getComputedStyle: () => ({getPropertyValue: () => ''})};
    vm.runInNewContext(fs.readFileSync(filename, 'utf8'), context, {filename});
    return {context, elements, links, BridgeDashboard};
}

test('Export PNG downloads the rendered spectrogram once the card is set up', () => {
    const d = dashboard();
    const owner = new d.BridgeDashboard();
    owner._initTabs();
    assert.equal(owner.tabsReady, true, 'the dashboard\'s own tab setup still runs');
    assert.ok(d.context.spectrogramViewer, 'tab setup creates the viewer');
    d.elements['sg-export-png'].click();
    assert.equal(d.links.length, 1);
    const [link] = d.links;
    assert.equal(link.tag, 'a');
    assert.equal(link.clicked, 1);
    assert.equal(link.href, 'data:image/png;base64,UE5H');
    assert.match(link.download, /^spectrogram_\d+\.png$/);
});

test('Export PNG is not bound before the viewer exists', () => {
    const d = dashboard();
    assert.equal(d.context.spectrogramViewer, null);
    d.elements['sg-export-png'].click();
    assert.equal(d.links.length, 0);
});

test('the card has no inline handler; the button is found by its id', () => {
    const html = fs.readFileSync(path.join(root, 'src/sigrift/bridge/templates/index.html'), 'utf8');
    const card = html.slice(html.indexOf('id="spectrogram-card"'), html.indexOf('id="spectrogram-canvas"'));
    assert.match(card, /<button type="button" id="sg-export-png" class="btn btn-sm btn-secondary">Export PNG<\/button>/);
    assert.doesNotMatch(card, /onclick=/);
    assert.match(html, /path='spectrogram_viewer\.js'\) \}\}\?v=(\d+)/);
    const version = Number(html.match(/path='spectrogram_viewer\.js'\) \}\}\?v=(\d+)/)[1]);
    assert.ok(version > 28, 'the cache-buster moved past the inline-handler release');
});
