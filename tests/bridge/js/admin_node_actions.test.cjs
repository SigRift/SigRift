/* Shipped admin node table: health badge and per-node action buttons. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const filename = path.resolve(__dirname, '../../../src/sigrift/bridge/static/admin.js');
const settle = () => new Promise(resolve => setImmediate(resolve));

class Element {
    constructor(attributes = {}) { this.attributes = attributes; this.events = {}; this.style = {}; this.html = ''; }
    get innerHTML() { return this.html; }
    set innerHTML(value) { this.html = value; }
    getAttribute(name) { return this.attributes[name]; }
    addEventListener(name, fn) { this.events[name] = fn; }
    click() { this.events.click.call(this, { stopPropagation() {}, target: { closest: () => this } }); }
}

/* What esc() builds: a <div> holding one text node, serialised like the DOM does. */
class TextHolder {
    constructor() { this.text = ''; }
    appendChild(node) { this.text += node.textContent; return node; }
    get innerHTML() { return this.text.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;'); }
}

/* Elements the rendered rows carry for one attribute selector such as "[data-run-diag]". */
function matching(html, selector) {
    const name = selector.slice(1, -1);
    const found = [];
    for (const match of html.matchAll(new RegExp(name + '="([^"]*)"', 'g'))) {
        found.push(new Element({ [name]: match[1] }));
    }
    return found;
}

function fixture(nodes) {
    const tbody = new Element(), requests = [], notices = [], opened = [], confirms = [];
    const elements = {};
    tbody.querySelectorAll = selector => (elements[selector] ||= matching(tbody.html, selector));
    const context = {
        console,
        document: {
            addEventListener() {}, createElement: () => new TextHolder(), createTextNode: textContent => ({ textContent }),
            getElementById: id => (id === 'admin-nodes-tbody' ? tbody : null),
        },
        window: {}, setTimeout() {},
    };
    vm.runInNewContext(fs.readFileSync(filename, 'utf8'), context, { filename });
    context.notify = (message, type) => notices.push([message, type]);
    context.confirmModal = options => { confirms.push(options); return Promise.resolve(true); };
    const panel = Object.create(context.AdminPanel.prototype);
    panel.apiFetch = async (url, options) => { requests.push({ url, options }); return {}; };
    panel._openNodeDetail = nodeId => opened.push(nodeId);
    panel._renderNodes(nodes);
    const button = selector => tbody.querySelectorAll(selector)[0];
    return { tbody, requests, notices, opened, confirms, button };
}

const healthOf = html => /node-health-(\w+)" title="([^"]*)"/.exec(html).slice(1);

test('Restart queues the restart command the node agent handles', async () => {
    const f = fixture([{ node_id: 'node-a', status: 'active' }]);
    assert.match(f.tbody.html, /data-restart-scanner="node-a" title="Restart every service on this node, including its agent"/);
    f.button('[data-restart-scanner]').click();
    await settle();
    assert.equal(f.confirms.length, 1);
    // The agent restarts every node service, itself last (node_agent._handle_restart)
    assert.equal(f.confirms[0].title, 'Restart node services');
    assert.match(f.confirms[0].message, /^Restart every service on node-a, including its agent\?/);
    assert.match(f.confirms[0].message, /within 5 minutes, the command is dropped\.$/);
    assert.deepEqual(JSON.parse(JSON.stringify(f.requests)), [{
        url: '/api/admin/nodes/node-a/command',
        options: { method: 'POST', body: { command: 'restart', params: {} } },
    }]);
    assert.deepEqual(f.notices, [['Restart command queued for node-a', 'success']]);
});

test('Diag opens the bridge diagnostics view instead of queuing a command', async () => {
    const f = fixture([{ node_id: 'node-a', status: 'active' }]);
    assert.match(f.tbody.html, /data-run-diag="node-a" title="Show node diagnostics"/);
    f.button('[data-run-diag]').click();
    await settle();
    assert.deepEqual(f.opened, ['node-a']);
    assert.deepEqual(f.requests, []);
});

for (const [name, node, expected] of [
    ['active and healthy', { status: 'active', cpu_percent: 10 }, ['green', 'Healthy']],
    ['active with critical CPU', { status: 'active', cpu_percent: 95 }, ['red', 'Critical']],
    ['active with elevated temperature', { status: 'active', capabilities: { cpu_temp: 75 } }, ['yellow', 'Degraded']],
    ['offline', { status: 'offline', cpu_percent: 10 }, ['red', 'Offline']],
    ['stale', { status: 'stale', cpu_percent: 80 }, ['yellow', 'Stale']],
    ['unknown', { status: 'unknown' }, ['yellow', 'Stale']],
    ['stale with critical CPU', { status: 'stale', cpu_percent: 95 }, ['red', 'Stale, critical']],
    ['unknown with critical temperature', { status: 'unknown', capabilities: { cpu_temp: 85 } }, ['red', 'Stale, critical']],
]) {
    test('health badge agrees with the diagnostics view: ' + name, () => {
        const f = fixture([{ node_id: 'node-a', ...node }]);
        assert.deepEqual(healthOf(f.tbody.html), expected);
    });
}
