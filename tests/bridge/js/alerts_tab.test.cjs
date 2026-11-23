/* The shipped Alerts tab (alerts.js + alert_analysis.js on top of
 * dashboard.js) in the parsed DOM of untrusted_dom.cjs: the Alert Feed's
 * filters, sorting, totals, acknowledgement, auto-refresh and timeline focus,
 * driven through the page's own controls and the real fetch and timer paths. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { bootDashboard, response, injected, settle } = require('./untrusted_dom.cjs');

const INDEX = fs.readFileSync(path.resolve(__dirname, '../../../src/sigrift/bridge/templates/index.html'), 'utf8');
const NAV = /<nav class="tab-bar" id="dashboard-tabs"[^>]*>([\s\S]*?)<\/nav>/.exec(INDEX)[1];
const TABLE = /<table class="data-table" id="alerts-tab-table">([\s\S]*?)<\/table>/.exec(INDEX)[1];
const CSRF = 'csrf-abc123';

const IDS = ['nav:dashboard-tabs', 'tab-summary', 'tab-alerts', 'select:alerts-tab-priority', 'select:alerts-tab-time', 'select:alerts-tab-node',
    'input:alerts-tab-hide-acked', 'input:alerts-tab-autorefresh', 'button:alerts-tab-refresh-btn', 'table:alerts-tab-table',
    'p:alerts-tab-empty', 'span:alerts-tab-badge', 'alerts-count-critical', 'alerts-count-warning', 'alerts-count-info', 'alerts-count-total',
    'alert-analysis-summary', 'alerts-list', 'canvas:threat-timeline-canvas', 'threat-timeline-summary'];

const now = Date.now();
const ago = minutes => new Date(now - minutes * 60000).toISOString();
const ALERTS = [
    { alert_id: 'a-crit', severity: 'critical', name: 'Jammer', message: 'Jamming detected', node_id: 'edge-1', triggered_at: ago(50) },
    { alert_id: 'a-warn', severity: 'warning', name: 'Rogue AP', message: 'Unknown AP', node_id: 'edge-2', triggered_at: ago(120), acknowledged: true },
    { alert_id: 'a-old', severity: 'info', name: 'Old', message: 'old news', node_id: 'edge-1', triggered_at: ago(30 * 60) },
    { alert_id: 'a-high', severity: 'high', name: 'High', message: 'loud', triggered_at: ago(10) },
    { alert_id: 'a-bare', triggered_at: ago(5) }];

/* Boot the dashboard, then construct the Alerts tab over the page's own
 * table head and tab bar, as the boot sequence does. */
function alertsTab({ alerts = () => ALERTS, nodes = [{ node_id: 'edge 1' }, { node_id: 'edge-2' }], routes = () => undefined } = {}) {
    const f = bootDashboard({ ids: IDS, routes: (url, options, call) => {
        const answer = routes(url, options, call);
        if (answer !== undefined) return answer;
        if (url.startsWith('/api/alerts/analysis')) return { alerts_considered: 0, frequencies: [], alert_types: [] };
        if (url.startsWith('/api/alerts/?') && !url.includes('limit=')) return alerts(url);
        if (url.startsWith('/api/nodes/?')) return nodes;
        return undefined;
    } });
    f.load('alerts.js', 'alert_analysis.js');
    f.el('alerts-tab-table').innerHTML = TABLE;
    // HTMLSelectElement.remove(index) removes that option (the stub's remove() detaches the element).
    const nodeSelect = f.el('alerts-tab-node'), detach = nodeSelect.remove.bind(nodeSelect);
    nodeSelect.remove = index => (index === undefined ? detach() : nodeSelect.options[index] && nodeSelect.options[index].remove());
    f.db.alertsDashboard = new f.context.AlertsDashboard(f.db);
    f.el('dashboard-tabs').innerHTML = NAV;
    f.db._initTabs();
    f.tab = name => f.el('dashboard-tabs').querySelector(`[data-tab="${name}"]`);
    f.rows = () => f.el('alerts-tab-tbody').querySelectorAll('tr[data-alert-id]').map(row => row.getAttribute('data-alert-id'));
    // Alert list queries (the feed and the Summary list), not the capped timeline or unacked-critical lookups.
    f.feedCalls = () => f.requests.filter(call => {
        const query = feedQuery(call.url);
        return query && query.slice(1).every(param => /^(severity|node_id)=/.test(param));
    });
    return f;
}
/* An /api/alerts/ list query as [path, ...params], sorted and without the cache-buster. */
function feedQuery(url) {
    const [base, query = ''] = url.split('?');
    if (base !== '/api/alerts/') return null;
    return [base, ...query.split('&').filter(param => param && !param.startsWith('_t=')).sort()];
}
const change = (f, el, value) => { el.value = value; el.dispatchEvent(new f.context.Event('change')); };
const check = (f, el, on) => { el.checked = on; el.dispatchEvent(new f.context.Event('change')); };
const alertSocket = f => f.sockets.find(socket => socket.url.endsWith('/api/alerts/ws/alerts'));
/* DOM nodes are compared by identity and named briefly on failure: assert's own
 * diff would print, and deepEqual would walk, the whole linked document. */
function describeNode(node) {
    if (!node || node.nodeType !== 1) return String(node);
    const id = node.getAttribute('data-alert-id');
    return `<${node.localName}${node.id ? '#' + node.id : ''}${id ? `[data-alert-id="${id}"]` : ''}>`
        + (node.ownerDocument.documentElement.contains(node) ? '' : ' (detached)');
}
function sameNode(actual, expected, message) {
    if (actual !== expected) assert.fail(`${message}: ${describeNode(actual)} is not ${describeNode(expected)}`);
}

test('the Alert Feed lists the selected window newest first with per-severity totals; Ack acknowledges exactly that alert', async () => {
    let ack = 200;
    const f = alertsTab({ routes: (url, options) => options.method === 'PUT' ? response(ack, {}) : undefined });
    await settle();
    const tbody = f.el('alerts-tab-tbody');
    assert.equal(tbody.textContent, '', 'nothing is fetched before the tab is opened');
    f.tab('alerts').click();
    assert.ok(tbody.textContent.includes('Loading alerts...'), 'the first load shows progress');
    await settle();
    assert.deepEqual(f.rows(), ['a-bare', 'a-high', 'a-crit', 'a-warn'], 'the 30 h old alert is outside the default 24 h window');
    const cells = id => tbody.querySelector(`tr[data-alert-id="${id}"]`).querySelectorAll('td').map(cell => cell.textContent);
    assert.deepEqual(cells('a-bare').slice(1), ['info', '--', '--', '--', 'Ack']);
    assert.deepEqual(cells('a-crit').slice(1), ['critical', 'Jammer', 'Jamming detected', 'edge-1', 'Ack']);
    assert.deepEqual(cells('a-warn').slice(1), ['warning', 'Rogue AP', 'Unknown AP', 'edge-2', 'Acked']);
    assert.equal(tbody.querySelector('tr[data-alert-id="a-warn"]').className, 'alerts-tab-row warning acknowledged');
    assert.deepEqual(['alerts-count-critical', 'alerts-count-warning', 'alerts-count-info', 'alerts-count-total', 'alerts-tab-badge']
        .map(id => f.el(id).textContent), ['1', '1', '1', '3', '4'], 'unknown severities count as info; "high" has no bucket');
    assert.equal(f.el('alerts-tab-empty').style.display, 'none');
    assert.equal(f.el('alerts-tab-table').querySelector('th[data-sort="triggered_at"]').className, 'sortable sort-desc');
    assert.ok(f.requests.some(call => call.url.startsWith('/api/alerts/analysis?hours=24&limit=10')), 'the analysis follows the feed window');

    const before = f.feedCalls().length;
    tbody.querySelector('[data-ack-alert-tab="a-crit"]').click();
    await settle();
    assert.deepEqual([f.lastWrite().method, f.lastWrite().url, f.lastWrite().headers['X-CSRF-Token']], ['PUT', '/api/alerts/a-crit/ack', CSRF]);
    assert.ok(f.toasts().includes('Alert acknowledged'));
    assert.ok(f.feedCalls().length - before >= 2, 'the feed and the Summary alert list both refresh');
    ack = 500;
    f.el('alerts-tab-tbody').querySelector('[data-ack-alert-tab="a-high"]').click();
    await settle();
    assert.equal(f.lastWrite().url, '/api/alerts/a-high/ack');
    assert.ok(f.toasts().includes('Failed to acknowledge alert'));
});

test('feed filters query by priority and exact node, and narrow the window or hide acknowledged alerts in place', async () => {
    let list = ALERTS.concat([{ alert_id: 'a-nodate', severity: 'info', triggered_at: 'not a date' }]);
    const f = alertsTab({ alerts: () => list });
    await settle();
    f.tab('alerts').click();
    await settle();
    const node = f.el('alerts-tab-node');
    assert.deepEqual(node.options.map(option => [option.value, option.textContent]), [['', 'All Nodes'], ['edge 1', 'edge 1'], ['edge-2', 'edge-2']]);
    const lastFeed = () => feedQuery(f.feedCalls().at(-1).url);

    change(f, f.el('alerts-tab-priority'), 'critical');
    await settle();
    assert.deepEqual(lastFeed(), ['/api/alerts/', 'severity=critical']);
    change(f, node, 'edge 1');
    await settle();
    assert.deepEqual(lastFeed(), ['/api/alerts/', 'node_id=edge%201', 'severity=critical']);
    change(f, f.el('alerts-tab-priority'), '');
    change(f, node, '');
    await settle();
    assert.deepEqual(lastFeed(), ['/api/alerts/']);

    change(f, f.el('alerts-tab-time'), '');
    await settle();
    assert.deepEqual(f.rows(), ['a-bare', 'a-high', 'a-crit', 'a-warn', 'a-old', 'a-nodate'], 'All time shows everything; an unreadable time sorts last');
    assert.ok(f.requests.some(call => call.url.startsWith('/api/alerts/analysis?hours=8760&')), 'and the analysis covers a year');
    change(f, f.el('alerts-tab-time'), '1');
    await settle();
    assert.deepEqual(f.rows(), ['a-bare', 'a-high', 'a-crit']);
    check(f, f.el('alerts-tab-hide-acked'), true);
    change(f, f.el('alerts-tab-time'), '168');
    await settle();
    assert.deepEqual(f.rows(), ['a-bare', 'a-high', 'a-crit', 'a-old'], 'the acknowledged alert stays hidden across a window change');
    check(f, f.el('alerts-tab-hide-acked'), false);
    await settle();
    assert.deepEqual(f.rows(), ['a-bare', 'a-high', 'a-crit', 'a-warn', 'a-old']);

    // Nothing left: an empty table and the empty-state message.
    list = [];
    f.el('alerts-tab-refresh-btn').click();
    await settle();
    assert.deepEqual([f.el('alerts-tab-tbody').children.length, f.el('alerts-tab-empty').style.display, f.el('alerts-tab-badge').textContent],
        [0, '', '0']);
    list = null;
    f.el('alerts-tab-refresh-btn').click();
    await settle();
    assert.equal(f.el('alerts-tab-tbody').children.length, 0, 'a null answer is an empty feed');

    // Reopening the tab rebuilds the node list and keeps the operator's choice.
    change(f, node, 'edge-2');
    f.tab('summary').click();
    f.tab('alerts').click();
    await settle();
    assert.deepEqual([node.options.length, node.value], [3, 'edge-2']);
});

test('sortable feed columns sort by priority rank, node or time and toggle direction on a second click', async () => {
    const f = alertsTab();
    await settle();
    f.tab('alerts').click();
    await settle();
    change(f, f.el('alerts-tab-time'), '');
    await settle();
    const header = field => f.el('alerts-tab-table').querySelector(`th[data-sort="${field}"]`);
    header('severity').click();
    assert.deepEqual(f.rows(), ['a-crit', 'a-high', 'a-warn', 'a-old', 'a-bare'], 'critical, high, warning, info, then unknown');
    assert.deepEqual([header('severity').className, header('triggered_at').className], ['sortable sort-asc', 'sortable']);
    header('severity').click();
    assert.deepEqual(f.rows(), ['a-bare', 'a-old', 'a-warn', 'a-high', 'a-crit']);
    assert.equal(header('severity').className, 'sortable sort-desc');
    header('node_id').click();
    assert.deepEqual(f.rows(), ['a-high', 'a-bare', 'a-crit', 'a-old', 'a-warn'], 'node A-Z, alerts without a node first');
    header('triggered_at').click();
    assert.deepEqual(f.rows(), ['a-bare', 'a-high', 'a-crit', 'a-warn', 'a-old'], 'time sorts newest first by default');
    header('triggered_at').click();
    assert.deepEqual(f.rows(), ['a-old', 'a-warn', 'a-crit', 'a-high', 'a-bare']);
    assert.equal(header('triggered_at').className, 'sortable sort-asc');
    header('name').click();
    assert.deepEqual(f.rows(), ['a-old', 'a-warn', 'a-crit', 'a-high', 'a-bare'], 'an unsortable column does nothing');
});

test('auto-refresh re-queries every 10 s only while the tab is open, visible and enabled', async () => {
    const f = alertsTab();
    await settle();
    const polls = async ms => { const before = f.feedCalls().length; await f.tick(ms); return f.feedCalls().length - before; };
    assert.equal(await polls(10000), 0, 'not before the tab is opened');
    f.tab('alerts').click();
    await settle();
    assert.equal(await polls(10000), 1);
    f.document.hidden = true;
    f.fire('visibilitychange');
    assert.equal(await polls(20000), 0, 'paused while the page is hidden');
    f.document.hidden = false;
    f.fire('visibilitychange');
    assert.equal(await polls(10000), 1);
    const auto = f.el('alerts-tab-autorefresh');
    check(f, auto, false);
    assert.equal(await polls(30000), 0, 'off when unticked');
    check(f, auto, true);
    assert.equal(await polls(10000), 1);
    f.tab('summary').click();
    assert.equal(await polls(30000), 0, 'stops when the operator leaves the tab');
    check(f, auto, false);
    check(f, auto, true);
    assert.equal(await polls(30000), 0, 'ticking the box elsewhere does not start it');
    f.tab('alerts').click();
    await settle();
    assert.equal(await polls(10000), 1);
});

test('opening an alert from the threat timeline focuses exactly its row after the Alerts tab refreshes', async () => {
    const f = alertsTab();
    await settle();
    f.tab('alerts').click();
    await settle();
    f.tab('summary').click();
    alertSocket(f).open();
    alertSocket(f).message({ alert_id: 'a-crit', severity: 'critical', name: 'Jammer', message: 'Jamming detected' });
    const canvas = f.el('threat-timeline-canvas');
    canvas.dispatchEvent(new f.context.Event('focus'));
    canvas.dispatchEvent(new f.context.Event('keydown', { key: 'Enter' }));
    await settle();
    assert.equal(f.el('dashboard-tabs').querySelector('.tab-btn.active').getAttribute('data-tab'), 'alerts');
    const row = f.el('alerts-tab-tbody').querySelector('tr[data-alert-id="a-crit"]');
    sameNode(f.document.activeElement, row, 'the re-rendered row has focus');
    assert.deepEqual([row.getAttribute('tabindex'), row.scrolledIntoView], ['-1', true]);

    // The focus request is used once: a later refresh leaves the operator's focus alone.
    f.document.activeElement = f.document.body;
    f.el('alerts-tab-refresh-btn').click();
    await settle();
    assert.ok(f.rows().includes('a-crit'));
    sameNode(f.document.activeElement, f.document.body, 'a manual refresh does not pull focus back to the row');
});

test('a failing feed keeps the last rows on screen and reports each outage once', async () => {
    let down = false;
    const f = alertsTab({ alerts: () => (down ? response(503, {}) : ALERTS) });
    await settle();
    f.tab('alerts').click();
    await settle();
    const shown = f.rows();
    down = true;
    await f.tick(20000);
    assert.deepEqual(f.toasts().filter(text => /alerts-tab/.test(text)), [], 'two misses are not reported');
    await f.tick(20000);
    assert.deepEqual(f.toasts().filter(text => /alerts-tab/.test(text)), ['Connection issue: alerts-tab failing']);
    assert.deepEqual(f.rows(), shown, 'the last good rows stay visible');
    down = false;
    await f.tick(10000);
    down = true;
    await f.tick(20000);
    assert.equal(f.toasts().filter(text => /alerts-tab/.test(text)).length, 1);
    await f.tick(10000);
    assert.equal(f.toasts().filter(text => /alerts-tab/.test(text)).length, 2, 'after a recovery, a new outage is reported again');
});

test('only alerts linked to an RF detection offer Mark as known', async () => {
    const f = alertsTab({ alerts: () => [{ alert_id: 'a-rf', severity: 'warning', triggered_at: ago(1), rf_detection_id: 'det-42' },
        { alert_id: 'a-plain', severity: 'warning', triggered_at: ago(2) }] });
    await settle();
    f.tab('alerts').click();
    await settle();
    const known = f.el('alerts-tab-tbody').querySelectorAll('[data-known-detection]');
    assert.deepEqual(known.map(button => [button.closest('tr').getAttribute('data-alert-id'), button.getAttribute('data-known-detection'), button.textContent]),
        [['a-rf', 'det-42', 'Mark as known…']]);
});

// rf_detection_id is a sensor-supplied detection_id (see the Summary alert attributes test in dashboard_security.test.cjs).
test('a detection ID cannot break out of the Alert Feed Mark-as-known attribute', async () => {
    const QUOTE = 'x" onmouseover="alert(3)" data-x="';
    const f = alertsTab({ alerts: () => [{ alert_id: 'a-rf', severity: 'warning', triggered_at: ago(1), rf_detection_id: QUOTE }] });
    await settle();
    f.tab('alerts').click();
    await settle();
    const tbody = f.el('alerts-tab-tbody');
    assert.deepEqual(injected(tbody), []);
    assert.equal(tbody.querySelector('[data-known-detection]').getAttribute('data-known-detection'), QUOTE);
});
