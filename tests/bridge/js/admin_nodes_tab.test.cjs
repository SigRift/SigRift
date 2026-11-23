/* The admin console's Nodes tab (admin.js): the fleet overview, the node
 * table, the floor-plan placement editor and the diagnostics view, driven
 * through the controls of templates/admin.html in the admin_dom.cjs stub
 * DOM. Heartbeat values here are well-formed numbers; hostile heartbeat
 * strings are covered by admin_console_security. */
const assert = require('node:assert/strict');
const test = require('node:test');
const { adminPage, noUnexpectedConsoleErrors, reply, FakeEvent, assertCookieWrite, call, cell } = require('./admin_dom.cjs');

test.afterEach(noUnexpectedConsoleErrors);

const lastToast = page => page.toasts().at(-1);
const nodeLists = page => page.requests.filter(r => r.method === 'GET' && r.url === '/api/admin/nodes').length;

const FLEET = [
    { node_id: 'edge-a', host: '10.0.0.2', status: 'active', cpu_percent: 92.5, memory_mb: 600, last_seen: '2026-11-10T11:59:00Z',
        detection_summary: { total_detections: 120, period_seconds: 60 }, capabilities: { cpu_temp: 81, uptime_seconds: 90061 },
        position_x: 25, position_y: 50 },
    { node_id: 'edge-b', host: '10.0.0.3', status: 'active', cpu_percent: 50, memory_mb: 400, classifications_per_sec: 0.5,
        capabilities: { last_error: 'SDR overflow at 2.4 MS/s' }, position_x: 75, position_y: 25 },
    { node_id: 'edge-c-with-a-long-name', host: '10.0.0.4', status: 'stale', cpu_percent: 80, capabilities: { cpu_temp: 72 },
        position_x: 50, position_y: 75 },
    { node_id: 'edge-d', host: '10.0.0.5', status: 'offline' },
    { node_id: 'edge-e', host: '10.0.0.6' },
];

async function nodesTab({ nodes = FLEET, routes = {} } = {}) {
    const server = { nodes };
    const page = await adminPage({ routes: { 'GET /api/admin/nodes': () => reply(200, server.nodes), ...routes } });
    page.server = server;
    await page.tab('nodes');
    return page;
}
const fleet = page => Object.fromEntries(['total', 'online', 'stale', 'offline', 'degraded', 'det-rate', 'avg-cpu', 'avg-mem']
    .map(name => [name, page.byId('fleet-' + name).textContent]));

test('the fleet overview counts nodes by state and explains each degraded node', async () => {
    const page = await nodesTab();
    assert.deepEqual(fleet(page), {
        total: '5', online: '2', stale: '1', offline: '2', degraded: '2', 'det-rate': '150.0', 'avg-cpu': '74.2', 'avg-mem': '500',
    });
    assert.deepEqual(page.byId('fleet-alerts-container').children.map(el => el.textContent),
        ['2 node(s) offline', 'edge-a: CPU 92.5%, Temp 81°C', 'edge-b: SDR overflow at 2.4 MS/s']);

    // A stale node with critical metrics is not counted as degraded: it is already stale.
    page.server.nodes = [{ node_id: 'quiet', status: 'stale', cpu_percent: 99, capabilities: { cpu_temp: 90 } }];
    await page.click(page.byId('admin-fleet-refresh'));
    assert.deepEqual(fleet(page), {
        total: '1', online: '0', stale: '1', offline: '0', degraded: '0', 'det-rate': '0.0', 'avg-cpu': '99.0', 'avg-mem': '--',
    });
    assert.equal(page.byId('fleet-alerts-container').innerHTML, '');

    page.server.nodes = [];
    await page.click(page.byId('admin-fleet-refresh'));
    assert.deepEqual(fleet(page), {
        total: '0', online: '0', stale: '0', offline: '0', degraded: '0', 'det-rate': '0.0', 'avg-cpu': '--', 'avg-mem': '--',
    });
    assert.equal(page.byId('admin-nodes-tbody').innerHTML, '');
    assert.equal(page.byId('admin-nodes-empty').style.display, '');
});

test('each node row shows its rate, load, temperature and uptime, and a health badge', async () => {
    const page = await nodesTab();
    const rows = page.byId('admin-nodes-tbody').querySelectorAll('tr');
    const read = row => ['Node', 'Status', 'Det/min', 'CPU', 'Mem', 'Temp', 'Uptime'].map(label => cell(row, label).textContent.trim());
    assert.deepEqual(rows.map(read), [
        ['edge-a', 'active', '120.0', '92.5', '600', '81°C', '1d 1h 1m'],
        ['edge-b', 'active', '30.0', '50.0', '400', '--', '--'],
        ['edge-c-with-a-long-name', 'stale', '--', '80.0', '--', '72°C', '--'],
        ['edge-d', 'offline', '--', '--', '--', '--', '--'],
        ['edge-e', 'unknown', '--', '--', '--', '--', '--'],
    ]);
    assert.deepEqual(rows.map(row => row.querySelector('.node-health').textContent.trim()), ['Critical', 'Healthy', 'Stale', 'Offline', 'Stale']);
    assert.equal(cell(rows[0], 'Seen').textContent, page.context.fmtTime(FLEET[0].last_seen));
    assert.equal(cell(rows[3], 'Seen').textContent, '--');
    assert.equal(page.byId('admin-nodes-empty').style.display, 'none');
});

test('each load and temperature threshold marks a node on its own, at the threshold\'s edge', async () => {
    // Active nodes, each with one measurement just at or just past one threshold.
    const probe = (node_id, cpu_percent, cpu_temp) => ({ node_id, status: 'active', cpu_percent, capabilities: cpu_temp == null ? {} : { cpu_temp } });
    const page = await nodesTab({
        nodes: [
            probe('cpu-75', 75), probe('cpu-75.5', 75.5), probe('cpu-85', 85), probe('cpu-85.5', 85.5), probe('cpu-90', 90), probe('cpu-90.5', 90.5),
            probe('temp-70', null, 70), probe('temp-71', null, 71), probe('temp-75', null, 75), probe('temp-76', null, 76),
            probe('temp-80', null, 80), probe('temp-81', null, 81),
        ],
    });
    const badges = Object.fromEntries(page.byId('admin-nodes-tbody').querySelectorAll('tr')
        .map(row => [cell(row, 'Node').textContent, row.querySelector('.node-health').textContent.trim()]));
    assert.deepEqual(badges, {
        'cpu-75': 'Healthy', 'cpu-75.5': 'Degraded', 'cpu-85': 'Degraded', 'cpu-85.5': 'Degraded', 'cpu-90': 'Degraded', 'cpu-90.5': 'Critical',
        'temp-70': 'Healthy', 'temp-71': 'Degraded', 'temp-75': 'Degraded', 'temp-76': 'Degraded', 'temp-80': 'Degraded', 'temp-81': 'Critical',
    });
    // The fleet overview counts a node as degraded above 85% CPU or 75°C.
    assert.equal(page.byId('fleet-degraded').textContent, '6');
    assert.deepEqual(page.byId('fleet-alerts-container').children.map(el => el.textContent), [
        'cpu-85.5: CPU 85.5%', 'cpu-90: CPU 90.0%', 'cpu-90.5: CPU 90.5%', 'temp-76: Temp 76°C', 'temp-80: Temp 80°C', 'temp-81: Temp 81°C',
    ]);
});

test('the placement list offers every node and keeps the chosen node across a refresh', async () => {
    const page = await nodesTab();
    const select = page.byId('admin-fp-node-select');
    assert.deepEqual(select.options.map(o => o.value), ['', 'edge-a', 'edge-b', 'edge-c-with-a-long-name', 'edge-d', 'edge-e']);
    select.value = 'edge-d';
    await page.click(page.byId('admin-fleet-refresh'));
    assert.equal(select.value, 'edge-d');
    assert.equal(select.options.length, 6, 'the list is rebuilt, not appended to');
    assert.equal(nodeLists(page), 2);
});

/* The calls of the last floor-plan drawing (everything after its clearRect). */
function lastDrawing(page) {
    const drawn = page.byId('admin-floorplan-canvas').drawn;
    const start = drawn.map(([method]) => method).lastIndexOf('clearRect');
    return drawn.slice(start);
}
const labels = drawing => drawing.filter(([method]) => method === 'fillText').map(([, text]) => text);

test('the floor plan draws each placed node with its (shortened) name, active nodes in green', async () => {
    const page = await nodesTab();
    const drawing = lastDrawing(page);
    assert.deepEqual(labels(drawing).filter(text => typeof text === 'string'), ['edge-a', 'edge-b', 'edge-c-with-..']);
    // Each dot's colour is the fill style in effect when its circle is filled.
    const dots = [];
    let fillStyle = null, circle = false;
    for (const [method, value] of drawing) {
        if (method === '=fillStyle') fillStyle = value;
        else if (method === 'arc') circle = true;
        else if (method === 'fill' && circle) { dots.push(fillStyle); circle = false; }
    }
    assert.deepEqual(dots, ['#3fb950', '#3fb950', '#8b949e']);
    const arcs = drawing.filter(([method]) => method === 'arc').map(([, x, y]) => [x, y]);
    assert.deepEqual(arcs, [[30 + 0.25 * 640, 30 + 0.5 * 340], [30 + 0.75 * 640, 30 + 0.25 * 340], [30 + 0.5 * 640, 30 + 0.75 * 340]]);
    assert.ok(!labels(drawing).includes('Select a node above, then click to place it.'));

    page.server.nodes = [{ node_id: 'unplaced', status: 'active' }, { node_id: 'half', status: 'active', position_x: 10 }];
    await page.click(page.byId('admin-fleet-refresh'));
    assert.deepEqual(labels(lastDrawing(page)).filter(text => typeof text === 'string'), [],
        'a node with only one coordinate is not drawn');
    page.server.nodes = [{ node_id: 'unplaced', status: 'active' }];
    await page.click(page.byId('admin-fleet-refresh'));
    assert.deepEqual(labels(lastDrawing(page)).filter(text => typeof text === 'string'), ['Select a node above, then click to place it.']);
});

const at = (x, y) => new FakeEvent('click', { clientX: x, clientY: y });

test('clicking the floor plan places the chosen node at that point, as a percentage of the plan', async () => {
    let refuse = false;
    const page = await nodesTab({
        routes: { 'PATCH /api/nodes/edge-d/position': () => (refuse ? reply(400, { detail: 'position out of range' }) : reply(200, {})) },
    });
    const canvas = page.byId('admin-floorplan-canvas');
    canvas.dispatchEvent(at(350, 200));
    await page.advance(0);
    assert.deepEqual(page.writes(), []);
    assert.deepEqual(lastToast(page), { text: 'Select a node from the dropdown first.', type: 'warning', markup: 0 });

    page.byId('admin-fp-node-select').value = 'edge-d';
    page.byId('admin-fp-floor-label').value = 'Floor 2';
    const before = nodeLists(page);
    for (const [x, y] of [[350, 200], [0, 0], [700, 400], [131, 77]]) canvas.dispatchEvent(at(x, y));
    await page.advance(0);
    assert.deepEqual(page.writes().map(call), [
        ['PATCH', '/api/nodes/edge-d/position', { x: 50, y: 50, floor_label: 'Floor 2' }],
        ['PATCH', '/api/nodes/edge-d/position', { x: 0, y: 0, floor_label: 'Floor 2' }],
        ['PATCH', '/api/nodes/edge-d/position', { x: 100, y: 100, floor_label: 'Floor 2' }],
        ['PATCH', '/api/nodes/edge-d/position', { x: 15.8, y: 13.8, floor_label: 'Floor 2' }],
    ]);
    assertCookieWrite(page.writes()[0]);
    assert.equal(nodeLists(page), before + 4, 'each placement reloads the fleet');

    refuse = true;
    canvas.dispatchEvent(at(350, 200));
    await page.advance(0);
    assert.deepEqual(lastToast(page), { text: 'Failed to set position: position out of range', type: 'error', markup: 0 });
});

test('moving over the floor plan shows the point under the pointer', async () => {
    const page = await nodesTab();
    const canvas = page.byId('admin-floorplan-canvas'), coords = page.byId('admin-fp-coords');
    canvas.dispatchEvent(new FakeEvent('mousemove', { clientX: 190, clientY: 115 }));
    assert.equal(coords.textContent, '(25, 25)');
    canvas.dispatchEvent(new FakeEvent('mousemove', { clientX: 5, clientY: 395 }));
    assert.equal(coords.textContent, '(0, 100)');
    await page.tab('nodes');
    canvas.dispatchEvent(new FakeEvent('mousemove', { clientX: 670, clientY: 30 }));
    assert.equal(coords.textContent, '(100, 0)', 'reopening the tab binds the plan once');
});

test('deregistering a node removes it from the fleet once confirmed', async () => {
    const page = await nodesTab({
        routes: { 'DELETE /api/admin/nodes/edge-d': () => { page.server.nodes = page.server.nodes.filter(n => n.node_id !== 'edge-d'); return reply(204); } },
    });
    await page.click(page.byId('admin-nodes-tbody').querySelector('[data-dereg="edge-d"]'));
    await page.click(page.button('Deregister'));
    assert.deepEqual(lastToast(page), { text: 'Node edge-d deregistered', type: 'success', markup: 0 });
    assert.equal(page.byId('admin-nodes-tbody').querySelector('[data-dereg="edge-d"]'), null);
    assert.equal(page.byId('fleet-total').textContent, '4');
});

test('a node command or config push the bridge refuses is reported for that node', async () => {
    const page = await nodesTab({
        routes: {
            'POST /api/admin/nodes/edge-a/command': () => reply(503),
            'PUT /api/admin/nodes/edge-a/config': () => reply(503),
            'DELETE /api/admin/nodes/edge-a': () => reply(500),
        },
    });
    const tbody = page.byId('admin-nodes-tbody');
    await page.click(tbody.querySelector('[data-restart-scanner="edge-a"]'));
    await page.click(page.button('Restart'));
    assert.deepEqual(lastToast(page), { text: 'Failed to queue restart command for edge-a', type: 'error', markup: 0 });
    await page.click(tbody.querySelector('[data-update-config="edge-a"]'));
    await page.click(page.button('Submit'));
    assert.deepEqual(lastToast(page), { text: 'Failed to queue config update for edge-a', type: 'error', markup: 0 });
    await page.click(tbody.querySelector('[data-dereg="edge-a"]'));
    await page.click(page.button('Deregister'));
    assert.deepEqual(lastToast(page), { text: 'Failed to deregister node: HTTP 500', type: 'error', markup: 0 });
});

/* ------------------------------------------------------------------ */
/* Diagnostics                                                         */
/* ------------------------------------------------------------------ */

const DIAGNOSTICS = {
    health: 'green',
    system_info: { cpu_percent: 12.34, memory_mb: 512.6, disk_percent: 40.26, cpu_temp: 55.4, load_1m: 0.456, accelerator: 'Hailo-8' },
    uptime_seconds: 3700,
    sdr_info: { sample_rate: 2.4e6, freq_range_min: 24e6, freq_range_max: 1766e6 },
    detection_stats: { total_detections: 300, rate_per_min: 4.26, avg_confidence: 0.8766, period_seconds: 3600.4,
        top_classes: [{ class: 'bpsk', count: 200 }, { class: 'fsk', count: 50 }, { class: 'ook', count: 0 }] },
    scanners: [{ name: 'RF', status: 'active', count: 5 }, { name: 'BT', status: 'idle' }],
    pending_commands: [{ command: 'restart', queued_at: '2026-11-10T11:30:00Z' }, { command: 'update_config', queued_at: null }],
    recent_errors: Array.from({ length: 25 }, (_, i) => ({ timestamp: '2026-11-10T11:00:00Z', action: 'error_' + i, message: 'm' + i })),
    latency_ms: 12.6,
};

async function diagnostics(answer) {
    const page = await nodesTab({ routes: { 'GET /api/admin/nodes/edge-a/diagnostics': () => answer() } });
    await page.click(page.byId('admin-nodes-tbody').querySelector('[data-run-diag="edge-a"]'));
    return page;
}
const items = body => Object.fromEntries(body.querySelectorAll('.node-detail-item').map(item =>
    [item.querySelector('.ndl').textContent, item.querySelector('.ndv').textContent]));

test('node diagnostics: measurements are shown with their units', async () => {
    const page = await diagnostics(() => reply(200, DIAGNOSTICS));
    const body = page.byId('node-detail-body');
    assert.deepEqual(items(body), {
        CPU: '12.3%', Memory: '513 MB', Disk: '40.3%', Temperature: '55°C', 'Load 1m': '0.46', OS: '--', Platform: '--',
        Python: '--', Agent: '--', Model: '--', Accelerator: 'Hailo-8', Uptime: '1h 1m',
        Type: '--', 'Capture Mode': '--', Serial: '--', Firmware: '--', 'Sample Rate': '2.4 MHz', 'Freq Min': '24.0 MHz', 'Freq Max': '1766.0 MHz',
        'Total Detections': '300', Rate: '4.3/min', 'Avg Confidence': '87.7%', 'Dominant Class': '--', 'Dominant Family': '--', Period: '3600s',
        'Heartbeat Latency': '13 ms',
    });
    const classes = body.querySelector('table').querySelectorAll('tbody tr');
    assert.deepEqual(classes.map(tr => [tr.children[0].textContent, tr.children[1].textContent, tr.children[2].firstChild.style.width]),
        [['bpsk', '200', '100%'], ['fsk', '50', '25%'], ['ook', '0', '0%']], 'bars are relative to the most common class');
    assert.deepEqual(body.querySelectorAll('.node-scanner-badge').map(el => el.textContent.trim()), ['RF — active (5)', 'BT — idle']);
    assert.match(body.textContent, /Pending Commands \(2\)restart queued at [^]+update_config queued at --/);
    assert.match(body.textContent, /Recent Audit\/Log Entries \(25\)/);
    assert.equal(body.querySelectorAll('.node-error-entry').length, 20, 'at most 20 recent entries are listed');
    assert.equal(body.querySelector('.node-error-msg').textContent, 'error_0: m0');
    assert.equal(body.firstChild.querySelector('strong').style.color, 'var(--accent-green)');
    assert.equal(body.querySelector('ul'), null, 'a healthy node lists no issues');
});

test('node diagnostics: the health banner is coloured by the reported health', async () => {
    for (const [health, color] of [['red', 'var(--accent-red)'], ['yellow', 'var(--accent-yellow)'], ['green', 'var(--accent-green)']]) {
        const page = await diagnostics(() => reply(200, { health, health_issues: health === 'green' ? [] : ['CPU above 90%'] }));
        const banner = page.byId('node-detail-body').firstChild;
        assert.equal(banner.querySelector('strong').textContent, 'Health: ' + health.toUpperCase());
        assert.equal(banner.querySelector('strong').style.color, color, health);
        assert.deepEqual(banner.querySelectorAll('li').map(li => li.textContent), health === 'green' ? [] : ['CPU above 90%']);
        assert.equal(page.byId('node-detail-body').textContent.includes('Pending Commands'), false, 'no pending section when none are queued');
        assert.equal(page.byId('node-detail-body').textContent.includes('Heartbeat Latency'), false, 'no latency when none is reported');
    }
});

test('the diagnostics view shows a loading state, then closes by its buttons or a click outside', async () => {
    let release;
    const page = await diagnostics(() => new Promise(resolve => { release = () => resolve(reply(200, { health: 'green' })); }));
    const modal = page.byId('node-detail-modal'), body = page.byId('node-detail-body');
    assert.equal(modal.style.display, '');
    assert.equal(page.byId('node-detail-title').textContent, 'Node Diagnostics: edge-a');
    assert.equal(body.textContent, 'Loading diagnostics...');
    release();
    await page.advance(0);
    assert.match(body.textContent, /^Health: GREEN/);

    await page.click(page.byId('node-detail-close'));
    assert.equal(modal.style.display, 'none');
    await page.click(page.byId('admin-nodes-tbody').querySelector('tr'));
    release();
    await page.advance(0);
    assert.equal(modal.style.display, '', 'clicking a row opens its diagnostics');
    await page.click(page.byId('node-detail-dismiss'));
    assert.equal(modal.style.display, 'none');
    await page.click(page.byId('admin-nodes-tbody').querySelector('[data-run-diag="edge-a"]'));
    release();
    await page.advance(0);
    modal.dispatchEvent(new FakeEvent('click', { target: body }));
    assert.equal(modal.style.display, '', 'a click inside the dialog keeps it open');
    modal.dispatchEvent(new FakeEvent('click'));
    assert.equal(modal.style.display, 'none');
    await page.key('Escape');
    assert.equal(modal.style.display, 'none', 'Escape on a closed dialog changes nothing');
});

test('a diagnostics failure without an explanation reports its HTTP status', async () => {
    const page = await diagnostics(() => new Response(null, { status: 502 }));
    assert.equal(page.byId('node-detail-body').textContent, 'Failed to load diagnostics: HTTP 502');
});
