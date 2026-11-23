const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const root = path.resolve(__dirname, '../../../src/sigrift/bridge/static');
const file = path.join(root, 'alert_analysis.js');
const source = fs.readFileSync(file, 'utf8');
const settle = () => new Promise(resolve => setImmediate(resolve));

class Element {
    constructor(tag) { this.tagName = tag; this.children = []; this.events = {}; this.attrs = {}; this.textContent = ''; this.value = ''; this.style = {}; this.checked = false; this.disabled = false; }
    appendChild(c) { this.children.push(c); c.parent = this; return c; }
    replaceChildren(...c) { this.children = []; c.forEach(x => this.appendChild(x)); }
    addEventListener(n, fn) { (this.events[n] ||= []).push(fn); }
    setAttribute(n, v) { this.attrs[n] = v; }
    remove() { if (this.parent) this.parent.children = this.parent.children.filter(c => c !== this); }
    showModal() { this.open = true; }
    close() { this.open = false; this.fire('close'); }
    fire(n) { for (const fn of this.events[n] || []) fn({ preventDefault() {} }); }
    click() { if (!this.disabled) this.fire('click'); }
}
const walk = n => [n, ...n.children.flatMap(walk)];

function fixture(responses, { hours = '24', includeAcked = false, readyState = 'complete' } = {}) {
    const ids = {};
    for (const id of ['alert-analysis-freq-body', 'alert-analysis-type-body', 'alert-analysis-freq-empty', 'alert-analysis-type-empty', 'alert-analysis-summary', 'alert-analysis-refresh', 'alert-analysis-include-acked', 'alerts-tab-time']) ids[id] = new Element('x');
    ids['alerts-tab-time'].value = hours;
    ids['alert-analysis-include-acked'].checked = includeAcked;
    const body = new Element('body'), requests = [], toasts = [], documentEvents = {};
    const context = { window: {}, showToast: (m) => toasts.push(m), document: { readyState, body, createElement: t => new Element(t), getElementById: id => ids[id] || null, addEventListener(n, fn) { (documentEvents[n] ||= []).push(fn); } } };
    vm.runInNewContext(source, context, { filename: file });
    const db = { apiFetch: async (url, options) => { requests.push({ url, options }); assert.ok(responses.length, 'unexpected request ' + url); const v = responses.shift(); if (v instanceof Error) throw v; return v; } };
    return { ids, body, requests, toasts, db, api: context.window.AlertAnalysis, fireDocument: n => (documentEvents[n] || []).forEach(fn => fn()) };
}

const group = {
    node_id: 'node-a', freq_min_hz: 433.91e6, freq_max_hz: 433.95e6, count: 3, open: 3,
    classes: [{ signal_class: 'ook', count: 2 }, { signal_class: '2fsk', count: 1 }],
    alert_types: [{ name: 'anomaly_detected', count: 2 }], latest: null, covered_by: [],
    suggested_pattern: { freq_min_hz: 433900000, freq_max_hz: 434000000, signal_class: '*', node_id: 'node-a' },
};
const analysis = (over = {}) => ({ alerts_considered: 4, unlinked_open: 1, frequencies_total: 1, can_manage: true, frequencies: [group], alert_types: [{ name: '<b>x</b>', count: 4, open: 4, severities: { warning: 4 }, top_frequencies: [{ node_id: 'node-a', freq_min_hz: 433.9e6, freq_max_hz: 434e6, count: 3 }] }], ...over });

test('renders groups as text and follows the feed window', async () => {
    const f = fixture([analysis()], { hours: '6', includeAcked: true });
    await f.api.refresh(f.db);
    assert.equal(f.requests[0].url, '/api/alerts/analysis?hours=6&limit=10&include_acknowledged=true');
    const freqRow = f.ids['alert-analysis-freq-body'].children[0];
    assert.equal(freqRow.children[0].textContent, '433.91–433.95 MHz');
    assert.equal(freqRow.children[4].textContent, '3 / 3');
    assert.equal(f.ids['alert-analysis-type-body'].children[0].children[0].textContent, '<b>x</b>');
    assert.match(f.ids['alert-analysis-summary'].textContent, /4 alert\(s\).*1 open alert\(s\) have no RF detection/);
    assert.equal(f.ids['alert-analysis-freq-empty'].style.display, 'none');
});

test('all-time feed window asks for a year; read-only users get no action', async () => {
    const f = fixture([analysis({ can_manage: false })], { hours: '' });
    await f.api.refresh(f.db);
    assert.match(f.requests[0].url, /hours=8760/);
    assert.equal(walk(f.ids['alert-analysis-freq-body']).some(n => n.tagName === 'button'), false);
});

test('covered groups show Already known instead of an action', async () => {
    const f = fixture([analysis({ frequencies: [{ ...group, covered_by: ['p1'] }] })]);
    await f.api.refresh(f.db);
    assert.ok(walk(f.ids['alert-analysis-freq-body']).some(n => n.textContent === 'Already known'));
});

test('mark known posts the reviewed scope, acks covered alerts and refreshes the feed', async () => {
    let feedRefreshed = 0;
    const f = fixture([analysis(), { pattern: { pattern_id: 'p1' }, acknowledged_count: 3 }, analysis()]);
    await f.api.refresh(f.db, () => { feedRefreshed += 1; });
    walk(f.ids['alert-analysis-freq-body']).find(n => n.tagName === 'button').click();
    const dialog = f.body.children[0];
    const field = name => walk(dialog).find(n => n.name === name);
    assert.equal(field('freq_min_mhz').value, '433.9');
    assert.equal(field('any_modulation').checked, true);
    assert.equal(field('acknowledge_covered').checked, true);
    field('note').value = 'garage remotes';
    walk(dialog).find(n => n.tagName === 'form').fire('submit');
    await settle(); await settle();
    assert.deepEqual(JSON.parse(JSON.stringify(f.requests[1].options.body)), { freq_min_hz: 433900000, freq_max_hz: 434000000, signal_class: '*', node_id: 'node-a', note: 'garage remotes', acknowledge_covered: true });
    assert.equal(dialog.open, false);
    assert.equal(feedRefreshed, 1);
    assert.match(f.toasts[0], /3 alert/);
});

test('all-nodes, specific class and invalid ranges are handled before posting', async () => {
    const f = fixture([new Error('Database unavailable')]);
    const dialog = f.api.open({ ...group, open: 0, suggested_pattern: { ...group.suggested_pattern, signal_class: 'ook' } }, f.db);
    const field = name => walk(dialog).find(n => n.name === name);
    const submit = () => walk(dialog).find(n => n.tagName === 'form').fire('submit');
    assert.equal(field('acknowledge_covered').checked, false);
    field('freq_max_mhz').value = '1';
    submit();
    assert.equal(f.requests.length, 0);
    assert.match(walk(dialog).find(n => n.attrs.role === 'status').textContent, /increasing/);
    field('freq_max_mhz').value = '434';
    field('all_nodes').checked = true; field('all_nodes').fire('change');
    assert.equal(field('node_id').disabled, true);
    submit();
    await settle(); await settle();
    assert.equal(f.requests[0].options.body.node_id, null);
    assert.equal(f.requests[0].options.body.signal_class, 'ook');
    assert.match(walk(dialog).find(n => n.attrs.role === 'status').textContent, /Database unavailable/);
});

test('a failed refresh says so', async () => {
    const f = fixture([new Error('down')]);
    await f.api.refresh(f.db);
    assert.match(f.ids['alert-analysis-summary'].textContent, /unavailable/);
});

test('single-frequency groups and missing optional fields render with placeholders; an empty window shows the empty states', async () => {
    const single = { ...group, freq_min_hz: 433.92e6, freq_max_hz: 433.92e6, classes: undefined, alert_types: undefined };
    const f = fixture([analysis({ frequencies: [single], frequencies_total: undefined, unlinked_open: 0,
        alert_types: [{ name: 'quiet', count: 1, open: 0 }] }), { alerts_considered: 0 }]);
    await f.api.refresh(f.db);
    const texts = row => row.children.map(cell => cell.textContent);
    assert.deepEqual(texts(f.ids['alert-analysis-freq-body'].children[0]).slice(0, 5), ['433.92 MHz', 'node-a', '', '', '3 / 3']);
    assert.deepEqual(texts(f.ids['alert-analysis-type-body'].children[0]), ['quiet', '', '—', '0 / 1']);
    assert.equal(f.ids['alert-analysis-summary'].textContent, '4 alert(s) in window · 0 frequency group(s) of 100 kHz');
    assert.equal(f.ids['alert-analysis-type-empty'].style.display, 'none');
    await f.api.refresh();
    assert.equal(f.requests.length, 2, 'a later refresh reuses the dashboard it was given');
    assert.deepEqual([f.ids['alert-analysis-freq-body'].children.length, f.ids['alert-analysis-type-body'].children.length], [0, 0]);
    assert.deepEqual([f.ids['alert-analysis-freq-empty'].style.display, f.ids['alert-analysis-type-empty'].style.display], ['', '']);
    assert.equal(f.ids['alert-analysis-summary'].textContent, '0 alert(s) in window · 0 frequency group(s) of 100 kHz');
});

test('a slower earlier refresh never overwrites a newer one, and an empty answer changes nothing', async () => {
    const f = fixture([]);
    await f.api.refresh();
    assert.equal(f.requests.length, 0, 'nothing to ask before a dashboard is attached');
    const pending = [];
    const db = { apiFetch: url => new Promise((resolve, reject) => pending.push({ url, resolve, reject })) };
    const first = f.api.refresh(db), second = f.api.refresh(db);
    pending[1].resolve(analysis({ alerts_considered: 9 }));
    await second;
    pending[0].resolve(analysis({ alerts_considered: 1 }));
    await first;
    assert.match(f.ids['alert-analysis-summary'].textContent, /^9 alert\(s\)/);
    const stale = f.api.refresh(db), latest = f.api.refresh(db);
    pending[3].resolve(null);
    await latest;
    pending[2].reject(new Error('timeout'));
    await stale;
    assert.match(f.ids['alert-analysis-summary'].textContent, /^9 alert\(s\)/, 'neither a stale failure nor a null answer replaces it');
    assert.equal(f.ids['alert-analysis-freq-body'].children.length, 1);
});

test('the mark-known dialog sends one save at a time and never claims an unconfirmed save', async () => {
    let finish;
    const answers = [];
    const db = { apiFetch: (url, options) => { answers.push(options.body); return new Promise((resolve, reject) => { finish = { resolve, reject }; }); } };
    const f = fixture([]);
    const dialog = f.api.open({ ...group, suggested_pattern: { ...group.suggested_pattern, node_id: undefined } }, db);
    const field = name => walk(dialog).find(n => n.name === name);
    const status = () => walk(dialog).find(n => n.attrs.role === 'status').textContent;
    const save = walk(dialog).find(n => n.textContent === 'Save known pattern');
    const submit = () => walk(dialog).find(n => n.tagName === 'form').fire('submit');
    assert.equal(field('node_id').value, '', 'a suggestion without a node leaves the node to the operator');
    submit();
    assert.equal(answers.length, 0);
    assert.match(status(), /a node or All nodes/);
    field('node_id').value = ' node-b ';
    submit();
    submit();
    assert.equal(answers.length, 1, 'a second submit while saving is ignored');
    assert.equal(answers[0].node_id, 'node-b');
    assert.deepEqual([status(), save.disabled], ['Saving…', true]);
    finish.resolve({ acknowledged_count: 0 });
    await settle(); await settle();
    assert.deepEqual([status(), save.disabled, dialog.open], ['The save was not confirmed. Refresh before retrying.', false, true]);
    submit();
    finish.reject({});
    await settle(); await settle();
    assert.equal(status(), 'Could not save. Nothing was confirmed; retry.');
    submit();
    finish.reject({ detail: 'Pattern overlaps an existing one' });
    await settle(); await settle();
    assert.equal(status(), 'Pattern overlaps an existing one');
    walk(dialog).find(n => n.textContent === 'Cancel').click();
    assert.equal(dialog.open, false);
    assert.equal(f.body.children.length, 0, 'a closed dialog is removed');
});

test('while the page is still loading, the toolbar is wired on DOMContentLoaded', async () => {
    const f = fixture([analysis(), analysis({ alerts_considered: 7 })], { readyState: 'loading' });
    await f.api.refresh(f.db);
    f.ids['alert-analysis-refresh'].click();
    assert.equal(f.requests.length, 1, 'not wired yet');
    f.fireDocument('DOMContentLoaded');
    f.ids['alert-analysis-include-acked'].checked = true;
    f.ids['alert-analysis-include-acked'].fire('change');
    await settle();
    assert.equal(f.requests.length, 2);
    assert.match(f.requests[1].url, /&include_acknowledged=true$/);
    assert.match(f.ids['alert-analysis-summary'].textContent, /^7 alert\(s\)/);
});
