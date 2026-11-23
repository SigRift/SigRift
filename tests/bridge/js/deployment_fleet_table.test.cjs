/* The shipped deployment panel (deployment.js) in the dashboard page: the
 * fleet comparison table an operator reads to find drift, and the per-node
 * Update/Restart commands. It runs with the real dashboard (apiFetch, esc,
 * fmtTime, the auth guard's CSRF wrapper) in untrusted_dom's parse5 DOM. */
const assert = require('node:assert/strict');
const test = require('node:test');
const { bootDashboard, response, settle, injected } = require('./untrusted_dom.cjs');

const IDS = ['deploy-table-wrap', 'deploy-empty', 'deploy-cache-info', 'button:deploy-refresh-btn'];

/* A dashboard whose GET /api/nodes/deployment answers `fleet()`; command
 * POSTs answer `command(nodeId, body)`. */
function page({ fleet, command = () => ({ status: 'queued' }) } = {}) {
    const state = { fleet };
    const f = bootDashboard({
        ids: IDS, scripts: ['deployment.js'],
        routes: (url, options) => {
            if (url.startsWith('/api/nodes/deployment')) return typeof state.fleet === 'function' ? state.fleet() : state.fleet;
            const match = /^\/api\/nodes\/([^/]+)\/command$/.exec(url);
            if (match && options.method === 'POST') return command(decodeURIComponent(match[1]), JSON.parse(options.body));
            return undefined;
        },
    });
    f.state = state;
    f.refresh = async () => { f.el('deploy-refresh-btn').click(); await settle(); };
    f.deployRequests = () => f.requests.filter(r => r.url.startsWith('/api/nodes/deployment') || /\/command$/.test(r.url))
        .map(r => r.method + ' ' + r.url.replace(/[?&]_t=\d+/, ''));
    return f;
}

/* The comparison table as an operator reads it: section -> property ->
 * one { text, cls } per node column, in node-id order. */
function grid(f) {
    const out = {};
    let section = '';
    for (const row of f.el('deploy-table-wrap').querySelectorAll('tbody tr')) {
        if (row.classList.contains('deploy-section-header')) { section = row.textContent; out[section] = {}; continue; }
        const [label, ...cells] = row.children;
        out[section][label.textContent] = cells.map(cell => ({
            text: cell.textContent,
            cls: (cell.getAttribute('class') || '').split(/\s+/).filter(name => name.startsWith('deploy-') && name !== 'deploy-cell').join(' '),
        }));
    }
    return out;
}
const texts = cells => cells.map(cell => cell.text);
const classes = cells => cells.map(cell => cell.cls);
const columns = f => f.el('deploy-table-wrap').querySelectorAll('thead th').slice(1).map(th => th.textContent);

/* untrusted_dom keeps element.dataset as a plain object; a browser derives
 * it from the data-* attributes, which the panel's click handlers read. */
function reflectDataset(f) {
    for (const el of f.el('deploy-table-wrap').querySelectorAll('[data-node]')) el.dataset.node = el.getAttribute('data-node');
}

const verified = extra => ({ reachable: true, ssh_status: 'verified', node_status: 'active', ...extra });

test('without a verified SSH audit, each node shows its contact, scanner reports and why the audit is missing', async () => {
    const f = page({
        fleet: {
            cached: true, cached_at: '2026-11-10T11:55:00Z', generated_at: '2026-11-10T12:00:00Z',
            nodes: {
                'n-active': { reachable: false, ssh_status: 'not_configured', node_status: 'active', last_seen: '2026-11-10T11:59:00Z',
                    guidance: 'Add an SSH target to audit this host.', hostname: 'pi-one',
                    scanner_status: { sdr: { active: true }, wifi: { state: 'error' }, bluetooth: { state: 'stopped' }, zigbee: { state: 'running' }, adsb: { active: false } } },
                'n-stale': { reachable: false, ssh_status: 'auth_failed', node_status: 'stale', error: 'Permission denied (publickey).' },
                'n-offline': { reachable: false, ssh_status: 'timeout', node_status: 'offline' },
                'n-silent': { reachable: false, node_status: 'unknown' },
                'n-new': { reachable: false },
            },
        },
    });
    await f.refresh();
    assert.deepEqual(columns(f), ['n-active' + 'pi-one', 'n-new', 'n-offline', 'n-silent', 'n-stale']);
    const g = grid(f);
    const time = f.context.fmtTime('2026-11-10T11:59:00Z');
    assert.deepEqual(texts(g['Node reports (no SSH required)']['Node contact']),
        ['Recent contact' + time, 'No contact reported', 'No recent contact', 'No contact reported', 'Stale contact']);
    assert.deepEqual(texts(g['Node reports (no SSH required)']['Scanner reports']),
        ['SDR: reportingWi-Fi: error reportedBluetooth: stoppedZigbee: report expiredADS-B: report expired',
            'No scanner report', 'No scanner report', 'No scanner report', 'No scanner report']);
    const audit = g['Optional SSH host audit']['Audit status'];
    assert.deepEqual(texts(audit), ['SSH audit not configuredAdd an SSH target to audit this host.', 'SSH audit failed',
        'SSH audit failed', 'SSH audit failed', 'Permission denied (publickey).']);
    assert.deepEqual(classes(audit), ['', 'deploy-warn', 'deploy-warn', 'deploy-warn', 'deploy-warn']);
    // No verified host: no host facts and no host commands to offer.
    assert.deepEqual(Object.keys(g), ['Node reports (no SSH required)', 'Optional SSH host audit']);
    assert.equal(f.el('deploy-table-wrap').querySelectorAll('button').length, 0);
    assert.equal(f.el('deploy-empty').style.display, 'none');
    assert.equal(f.el('deploy-cache-info').textContent, 'Updated ' + f.context.fmtTime('2026-11-10T12:00:00Z')
        + '; SSH audits: 0 verified, 1 not configured, 4 failed (host audit cached at ' + f.context.fmtTime('2026-11-10T11:55:00Z') + ')');
    assert.deepEqual(f.deployRequests(), ['GET /api/nodes/deployment?refresh=true']);
});

// Script-bearing markup a node (or its SSH audit output) could report: it
// must only ever reach the table as text. No double quotes: attribute
// break-out is the separate quote-escaping bug held below.
const MARKUP = '<img src=x onerror=alert(1)><script>alert(2)</script>';

test('strings a node reports cannot add markup to the comparison table', async () => {
    const f = page({
        fleet: {
            nodes: {
                'edge-1': verified({
                    hostname: MARKUP, ip: MARKUP, mac: MARKUP, os: MARKUP, kernel: MARKUP, python: MARKUP,
                    link: { type: 'wifi', interface: MARKUP, ssid: MARKUP, signal_dbm: -50 },
                    firewall: { active: true, policy: MARKUP }, model: { filename: MARKUP },
                    old_scripts: [{ name: MARKUP, path: MARKUP }, { name: 'node.py', path: '/home/pi/node.py' }],
                    config_checksums: { 'rf_scan.py': MARKUP },
                }),
                'edge-2': verified({ link: { type: MARKUP }, config_checksums: { 'rf_scan.py': MARKUP + 'x' } }),
                'edge-3': { reachable: false, ssh_status: 'auth_failed', hostname: MARKUP, error: MARKUP, guidance: MARKUP },
            },
        },
    });
    await f.refresh();
    const wrap = f.el('deploy-table-wrap');
    assert.deepEqual(injected(wrap), []);
    // The markup stays inside its own cell: the table keeps one heading per node and one cell per node in every row.
    assert.equal(columns(f).length, 3);
    for (const row of wrap.querySelectorAll('tbody tr:not(.deploy-section-header)')) assert.equal(row.children.length, 4, row.children[0].textContent);
    assert.ok(wrap.querySelectorAll('tbody td').every(td => td.querySelectorAll('td, th, tr').length === 0));
});

test('a script hash a node reports cannot add markup to its cell', async () => {
    const f = page({ fleet: { nodes: { 'edge-1': verified({ script_versions: { 'rf_scan.py': { hash: '<form>aaaaaaaa', mtime: 1 } } }) } } });
    await f.refresh();
    assert.deepEqual(injected(f.el('deploy-table-wrap')), []);
});

test('a legacy script path with a double quote cannot add attributes to its cell', async () => {
    const f = page({ fleet: { nodes: { 'edge-1': verified({ old_scripts: [{ name: 'monitor.py', path: '/home/pi/x" onmouseover="alert(3)/monitor.py' }] }) } } });
    await f.refresh();
    assert.deepEqual(injected(f.el('deploy-table-wrap')), []);
});

test('text a node reports is shown as written, not with HTML entities', async () => {
    const f = page({ fleet: { nodes: { a: verified({ link: { type: 'wifi', ssid: 'Ops & Lab' }, model: { filename: 'rf&v3.onnx' } }) } } });
    await f.refresh();
    const g = grid(f);
    assert.equal(g['System Info']['Link Detail'][0].text, 'Ops & Lab');
    assert.deepEqual(g['ONNX Model']['ONNX Model'][0], { text: 'rf&v3.onnx', cls: 'deploy-ok' });
});

test('interfaces, firewall policies and model names with & < > or quotes are shown once-escaped and compared as written', async () => {
    const odd = 'a&b<c>"d\'';
    const f = page({
        fleet: {
            nodes: {
                a: verified({ link: { type: 'wifi', interface: odd, ssid: odd }, firewall: { active: true, policy: odd }, model: { filename: odd } }),
                b: verified({ link: { type: 'ethernet', interface: odd }, firewall: { active: true }, model: { filename: odd } }),
                c: verified({ model: { filename: 'other.onnx' } }),
            },
        },
    });
    await f.refresh();
    assert.deepEqual(injected(f.el('deploy-table-wrap')), []);
    const g = grid(f);
    assert.deepEqual(texts(g['System Info']['Link Type']).slice(0, 2), ['WiFi (' + odd + ')', 'Ethernet (' + odd + ')']);
    assert.equal(g['System Info']['Link Detail'][0].text, odd);
    assert.deepEqual(texts(g.Security.Firewall), ['active (' + odd + ')', 'active ()', 'unknown']);
    assert.deepEqual(g['ONNX Model']['ONNX Model'], [{ text: odd, cls: 'deploy-ok' }, { text: odd, cls: 'deploy-ok' }, { text: 'other.onnx', cls: 'deploy-warn' }]);
});

test('a reply without a node map is an empty inventory, not an error', async () => {
    const f = page({ fleet: { cached: false } });
    await f.refresh();
    assert.equal(f.el('deploy-table-wrap').innerHTML, '');
    assert.equal(f.el('deploy-empty').style.display, '');
    assert.match(f.el('deploy-empty').textContent, /^No registered nodes\./);
    assert.equal(f.el('deploy-cache-info').textContent, 'No registered nodes');
    assert.equal(f.el('deploy-refresh-btn').disabled, false);
    assert.equal(f.el('deploy-refresh-btn').textContent, 'Refresh');
});

test('host facts: link, OS and package versions are compared across the verified nodes', async () => {
    const f = page({
        fleet: {
            generated_at: '2026-11-10T12:00:00Z',
            nodes: {
                a: verified({ ip: '10.0.0.2', mac: 'aa:01', os: 'Debian 12', kernel: '6.1', python: '3.11', numpy: '1.26',
                    link: { type: 'wifi', interface: 'wlan0', ssid: 'Ops', signal_dbm: -61 }, uptime_seconds: 7260 }),
                b: verified({ ip: '10.0.0.3', os: 'Debian 12', kernel: '6.6', python: '3.11', numpy: '2.0',
                    link: { type: 'ethernet', interface: 'eth0', speed_mbps: 1000 }, uptime_seconds: 0 }),
                c: verified({ os: 'Ubuntu 24.04', kernel: '6.1', python: '3.12', link: { type: 'wifi', signal_dbm: null } }),
                d: verified({ os: 'Debian 12', kernel: '6.1', python: '3.11', link: { type: 'ethernet' } }),
                e: verified({ os: 'Debian 12', kernel: '6.1', python: '3.11', link: { type: 'lte' } }),
                f: verified({ os: 'Debian 12', kernel: '6.1', python: '3.11' }),
                x: { reachable: false, ssh_status: 'not_configured', os: 'Windows', kernel: 'nt' },
            },
        },
    });
    await f.refresh();
    const info = grid(f)['System Info'], packages = grid(f).Packages;
    assert.deepEqual(texts(info['IP Address']), ['10.0.0.2', '10.0.0.3', 'unknown', 'unknown', 'unknown', 'unknown', '--']);
    assert.deepEqual(classes(info['IP Address']), ['', '', 'deploy-bad', 'deploy-bad', 'deploy-bad', 'deploy-bad', 'deploy-unreachable']);
    assert.deepEqual(texts(info['Link Type']), ['WiFi (wlan0)', 'Ethernet (eth0)', 'WiFi ()', 'Ethernet ()', 'lte', 'unknown', '--']);
    assert.deepEqual(texts(info['Link Detail']), ['Ops / -61 dBm', '1000 Mbps', '?', '? Mbps', '--', '--', '--']);
    // The fleet's most common value is the expected one (see the next test for who votes).
    assert.deepEqual(texts(info.OS), ['Debian 12', 'Debian 12', 'Ubuntu 24.04', 'Debian 12', 'Debian 12', 'Debian 12', '--']);
    assert.deepEqual(classes(info.OS), ['deploy-ok', 'deploy-ok', 'deploy-warn', 'deploy-ok', 'deploy-ok', 'deploy-ok', 'deploy-unreachable']);
    assert.deepEqual(classes(info.Kernel), ['deploy-ok', 'deploy-warn', 'deploy-ok', 'deploy-ok', 'deploy-ok', 'deploy-ok', 'deploy-unreachable']);
    assert.deepEqual(texts(info.Uptime), [f.context.fmtUptime(7260), f.context.fmtUptime(0), '--', '--', '--', '--', '--']);
    assert.deepEqual(classes(packages.Python), ['deploy-ok', 'deploy-ok', 'deploy-warn', 'deploy-ok', 'deploy-ok', 'deploy-ok', 'deploy-unreachable']);
    assert.deepEqual(texts(packages.NumPy), ['1.26', '2.0', 'unknown', 'unknown', 'unknown', 'unknown', '--']);
    // "unknown" wins the vote here, so a reported version is the odd one out; unknown itself is still bad.
    assert.deepEqual(classes(packages.NumPy), ['deploy-warn', 'deploy-warn', 'deploy-bad', 'deploy-bad', 'deploy-bad', 'deploy-bad', 'deploy-unreachable']);
    assert.match(f.el('deploy-cache-info').textContent, /6 verified, 1 not configured, 0 failed$/);
});

test('a node without a verified SSH audit does not vote on the versions or model the fleet expects', async () => {
    // Three nodes whose audit failed still carry facts from an older audit;
    // they outnumber the two verified nodes, so a vote of theirs would flip
    // every reference value and mark the up-to-date nodes as drifted.
    const old = { os: 'Debian 11', kernel: '5.10', python: '3.9', model: { filename: 'rf-v2.onnx' } };
    const f = page({
        fleet: {
            nodes: {
                a: verified({ os: 'Debian 12', kernel: '6.1', python: '3.11', model: { filename: 'rf-v3.onnx' } }),
                b: verified({ os: 'Debian 12', kernel: '6.1', python: '3.11', model: { filename: 'rf-v3.onnx' } }),
                x: { reachable: false, ssh_status: 'timeout', ...old },
                y: { reachable: false, ssh_status: 'auth_failed', ...old },
                z: { reachable: false, ssh_status: 'not_configured', ...old },
            },
        },
    });
    await f.refresh();
    const g = grid(f);
    const verdicts = cells => classes(cells).slice(0, 2);
    assert.deepEqual(verdicts(g['System Info'].OS), ['deploy-ok', 'deploy-ok']);
    assert.deepEqual(verdicts(g['System Info'].Kernel), ['deploy-ok', 'deploy-ok']);
    assert.deepEqual(verdicts(g.Packages.Python), ['deploy-ok', 'deploy-ok']);
    assert.deepEqual(verdicts(g['ONNX Model']['ONNX Model']), ['deploy-ok', 'deploy-ok']);
    assert.deepEqual(texts(g['ONNX Model']['ONNX Model']), ['rf-v3.onnx', 'rf-v3.onnx', '--', '--', '--']);
});

test('services, script versions, legacy scripts and config checksums flag drift per verified node', async () => {
    const f = page({
        fleet: {
            nodes: {
                a: verified({
                    services: { 'rf-edge': { active: true, enabled: true }, 'mlrf-agent': { active: true, enabled: false }, 'wifi-scan': { active: false, enabled: true } },
                    script_versions: { 'rf_scan.py': { hash: 'aaaaaaaa1111', mtime: 200 }, 'node_agent.py': { hash: 'missing', mtime: 900 } },
                    old_scripts: [],
                    config_checksums: { 'rf_scan.py': 'c1c1c1c1c1c1', 'node_agent.py': 'n1n1n1n1n1' },
                }),
                b: verified({
                    services: { 'rf-edge': { active: false, enabled: false } },
                    script_versions: { 'rf_scan.py': { hash: 'bbbbbbbb2222', mtime: 100 }, 'node_agent.py': { hash: 'nnnnnnnn3333', mtime: 50 } },
                    old_scripts: [{ name: 'old_scan.py', path: '/opt/old_scan.py' }, { name: 'legacy.sh', path: '/opt/legacy.sh' }],
                    config_checksums: { 'rf_scan.py': 'c2c2c2c2c2c2' },
                }),
                c: verified({
                    script_versions: { 'rf_scan.py': { hash: 'aaaaaaaa1111', mtime: 200 } },
                    config_checksums: { 'rf_scan.py': 'c1c1c1c1c1c1', 'node_agent.py': 'n1n1n1n1n1' },
                }),
                d: verified({}),
                z: { reachable: false, ssh_status: 'timeout', script_versions: { 'rf_scan.py': { hash: 'zzzzzzzz9999', mtime: 999 } },
                    old_scripts: [{ name: 'ignored.py', path: '/x' }], config_checksums: { 'rf_scan.py': 'zzz' } },
            },
        },
    });
    await f.refresh();
    const g = grid(f);
    const services = g.Services;
    assert.deepEqual(texts(services['rf-edge']), ['active / enabled', 'inactive / disabled', 'missing', 'missing', '--']);
    assert.deepEqual(classes(services['rf-edge']), ['deploy-ok', 'deploy-bad', 'deploy-bad', 'deploy-bad', 'deploy-unreachable']);
    assert.deepEqual(texts(services['mlrf-agent']).slice(0, 2), ['active / disabled', 'missing']);
    assert.deepEqual(classes(services['mlrf-agent']).slice(0, 2), ['deploy-warn', 'deploy-bad']);
    assert.deepEqual(texts(services['wifi-scan'])[0], 'inactive / enabled');
    assert.deepEqual(classes(services['wifi-scan'])[0], 'deploy-bad');

    // The most recently modified hash is current; an older one drifts. An
    // unreachable node's newer file does not move the reference.
    const scripts = g['Script Versions'];
    assert.deepEqual(texts(scripts['rf_scan.py']), ['aaaaaaaa', 'bbbbbbbb', 'aaaaaaaa', 'missing', '--']);
    assert.deepEqual(classes(scripts['rf_scan.py']), ['deploy-ok', 'deploy-warn', 'deploy-ok', 'deploy-bad', 'deploy-unreachable']);
    const hashCells = f.el('deploy-table-wrap').querySelectorAll('td[title]');
    assert.ok(hashCells.some(td => td.getAttribute('title') === 'bbbbbbbb2222'), 'the full hash is in the cell title');
    // A file reported "missing" is never the reference version.
    assert.deepEqual(texts(scripts['node_agent.py']), ['missing', 'nnnnnnnn', 'missing', 'missing', '--']);
    assert.deepEqual(classes(scripts['node_agent.py']), ['deploy-bad', 'deploy-ok', 'deploy-bad', 'deploy-bad', 'deploy-unreachable']);
    assert.deepEqual(texts(scripts['Legacy Scripts']), ['clean', 'old_scan.py, legacy.sh', 'clean', 'clean', '--']);
    assert.deepEqual(classes(scripts['Legacy Scripts']), ['deploy-ok', 'deploy-bad', 'deploy-ok', 'deploy-ok', 'deploy-unreachable']);
    assert.ok(hashCells.some(td => td.getAttribute('title') === '/opt/old_scan.py, /opt/legacy.sh'), 'legacy script paths are in the title');

    const config = g['Config Checksums'];
    assert.deepEqual(texts(config['rf_scan.py']), ['c1c1c1c1', 'DRIFT c2c2c2c2', 'c1c1c1c1', 'missing', 'Unavailable without a verified SSH audit']);
    assert.deepEqual(classes(config['rf_scan.py']), ['deploy-ok', 'deploy-bad', 'deploy-ok', '', '']);
    assert.deepEqual(texts(config['node_agent.py']), ['n1n1n1n1', 'missing', 'n1n1n1n1', 'missing', 'Unavailable without a verified SSH audit']);
    assert.deepEqual(texts(config['edge_inference.py']).slice(0, 4), ['missing', 'missing', 'missing', 'missing']);
});

test('a fleet without legacy scripts has no Legacy Scripts row', async () => {
    const f = page({ fleet: { nodes: { a: verified({ old_scripts: [] }), b: verified({}), z: { reachable: false, old_scripts: [{ name: 'x', path: 'y' }] } } } });
    await f.refresh();
    assert.equal('Legacy Scripts' in grid(f)['Script Versions'], false);
});

test('security, disk, memory and model rows judge each verified node', async () => {
    const f = page({
        fleet: {
            nodes: {
                a: verified({ firewall: { active: true, policy: 'deny' }, ssh: { password_auth: false, root_login: false },
                    api_keys_unified: true, api_keys_consistent: true, api_key_bridge_valid: true,
                    disk_used_pct: 60, disk_avail_gb: 12.5, ram_used_mb: 512, ram_total_mb: 1024,
                    model: { filename: 'rf-v3.onnx', size_bytes: 5767168 } }),
                b: verified({ firewall: { active: false }, ssh: { password_auth: true, root_login: true },
                    api_keys_unified: false, api_keys_consistent: false, api_key_bridge_valid: false,
                    disk_used_pct: 80, model: { filename: 'rf-v2.onnx' } }),
                c: verified({ disk_used_pct: 81, model: { filename: 'rf-v3.onnx', size_bytes: 0 } }),
                d: verified({ disk_used_pct: 61, model: {} }),
                z: { reachable: false, ssh_status: 'not_configured', model: { filename: 'rf-v2.onnx' } },
            },
        },
    });
    await f.refresh();
    const g = grid(f), security = g.Security, disk = g['Disk / Memory'], model = g['ONNX Model'];
    const row = (cells, n = 4) => cells.slice(0, n);
    assert.deepEqual(row(texts(security.Firewall)), ['active (deny)', 'INACTIVE', 'unknown', 'unknown']);
    assert.deepEqual(row(classes(security.Firewall)), ['deploy-ok', 'deploy-bad', 'deploy-bad', 'deploy-bad']);
    assert.deepEqual(row(texts(security['Password Auth'])), ['disabled', 'YES', 'unknown', 'unknown']);
    assert.deepEqual(row(classes(security['Password Auth'])), ['deploy-ok', 'deploy-bad', 'deploy-bad', 'deploy-bad']);
    assert.deepEqual(row(texts(security['Root Login'])), ['disabled', 'YES', 'unknown', 'unknown']);
    assert.deepEqual(row(classes(security['Root Login'])), ['deploy-ok', 'deploy-bad', 'deploy-bad', 'deploy-bad']);
    assert.deepEqual(row(texts(security['API Keys (node)'])), ['unified', 'FRAGMENTED', 'FRAGMENTED', 'FRAGMENTED']);
    assert.deepEqual(row(classes(security['API Keys (node)'])), ['deploy-ok', 'deploy-bad', 'deploy-bad', 'deploy-bad']);
    assert.deepEqual(row(texts(security['Keys (fleet)'])), ['shared key', 'unique per node', '--', '--']);
    assert.deepEqual(row(texts(security['Key (Bridge)'])), ['valid', 'INVALID', '--', '--']);
    assert.deepEqual(row(classes(security['Key (Bridge)'])), ['deploy-ok', 'deploy-bad', '', '']);
    assert.deepEqual(security.Firewall[4], { text: '--', cls: 'deploy-unreachable' });

    // Above 60% warns, above 80% is bad: each value sits on one side of a threshold.
    assert.deepEqual(row(texts(disk['Disk Used'])), ['60%', '80%', '81%', '61%']);
    assert.deepEqual(row(classes(disk['Disk Used'])), ['deploy-ok', 'deploy-warn', 'deploy-bad', 'deploy-warn']);
    assert.deepEqual(row(texts(disk['Disk Avail'])), ['12.5 GB', '--', '--', '--']);
    assert.deepEqual(row(texts(disk.RAM)), ['512 / 1024 MB', '--', '--', '--']);

    // The model most verified nodes run is the reference.
    assert.deepEqual(row(texts(model['ONNX Model'])), ['rf-v3.onnx', 'rf-v2.onnx', 'rf-v3.onnx', 'none']);
    assert.deepEqual(row(classes(model['ONNX Model'])), ['deploy-ok', 'deploy-warn', 'deploy-ok', 'deploy-bad']);
    assert.deepEqual(row(texts(model['Model Size'])), ['5.5 MB', '--', '--', '--']);
});

test('a verified node that reports no disk usage is not shown as healthy', async () => {
    const f = page({ fleet: { nodes: { a: verified({ disk_used_pct: 30 }), b: verified({}) } } });
    await f.refresh();
    assert.notEqual(grid(f)['Disk / Memory']['Disk Used'][1].cls, 'deploy-ok');
});

test('an unreported disk usage is uncolored; a reported 0% is healthy', async () => {
    const f = page({ fleet: { nodes: { a: verified({ disk_used_pct: 0 }), b: verified({ disk_used_pct: null }), c: verified({}) } } });
    await f.refresh();
    assert.deepEqual(grid(f)['Disk / Memory']['Disk Used'], [{ text: '0%', cls: 'deploy-ok' }, { text: '--', cls: '' }, { text: '--', cls: '' }]);
});

test('Update and Restart queue one command for that node only, with CSRF, then reload the cached audit', async () => {
    const commands = [];
    const f = page({
        fleet: { nodes: { 'edge-1': verified({}), 'edge-2': verified({}), 'edge-3': { reachable: false, ssh_status: 'timeout' } } },
        command: (node, body) => { commands.push([node, body]); return { queued: true }; },
    });
    await f.refresh();
    const g = grid(f);
    assert.deepEqual(texts(g.Actions.Update), ['Update', 'Update', 'Unavailable without a verified SSH audit']);
    assert.deepEqual(texts(g.Actions.Restart), ['Restart', 'Restart', 'Unavailable without a verified SSH audit']);
    reflectDataset(f);
    const buttons = () => f.el('deploy-table-wrap').querySelectorAll('button')
        .map(b => [b.getAttribute('data-node'), b.textContent, b.disabled, b.classList.contains('btn-success')]);

    f.el('deploy-table-wrap').querySelector('.deploy-update-btn[data-node="edge-2"]').click();
    assert.deepEqual(buttons(), [
        ['edge-1', 'Update', false, false], ['edge-2', 'Updating...', true, false],
        ['edge-1', 'Restart', false, false], ['edge-2', 'Updating...', true, false],
    ], 'both of that node\'s buttons wait for the command');
    await settle();
    assert.deepEqual(commands, [['edge-2', { command: 'update', params: {} }]]);
    const post = f.writes()[0];
    assert.equal(post.url, '/api/nodes/edge-2/command');
    assert.equal(post.headers['Content-Type'], 'application/json');
    assert.equal(post.headers['X-CSRF-Token'], 'csrf-abc123');
    assert.deepEqual(buttons().filter(b => b[0] === 'edge-2'), [['edge-2', 'Queued', true, true], ['edge-2', 'Queued', true, true]]);

    f.el('deploy-table-wrap').querySelector('.deploy-restart-btn[data-node="edge-1"]').click();
    await settle();
    assert.deepEqual(commands[1], ['edge-1', { command: 'restart', params: {} }]);
    assert.deepEqual(buttons().filter(b => b[0] === 'edge-1').map(b => b[1]), ['Queued', 'Queued']);

    // Each queued command reloads the cached audit (no forced SSH re-scan) 3 s later.
    assert.deepEqual(f.deployRequests().filter(r => r.startsWith('GET')), ['GET /api/nodes/deployment?refresh=true']);
    await f.tick(2999);
    assert.equal(f.deployRequests().filter(r => r.startsWith('GET')).length, 1);
    await f.tick(1);
    assert.deepEqual(f.deployRequests().filter(r => r.startsWith('GET')),
        ['GET /api/nodes/deployment?refresh=true', 'GET /api/nodes/deployment', 'GET /api/nodes/deployment']);
    assert.deepEqual(f.dialogs, []);
});

async function refusedCommand(refusal) {
    const f = page({ fleet: { nodes: { 'edge-1': verified({}) } }, command: () => refusal() });
    await f.refresh();
    reflectDataset(f);
    const [update, restart] = f.el('deploy-table-wrap').querySelectorAll('button');
    return { f, update, restart };
}

test('a refused command re-enables that node\'s buttons and says why', async () => {
    let refusal = response(503, { detail: 'agent offline' });
    const { f, update, restart } = await refusedCommand(() => refusal);
    restart.click();
    await settle();
    assert.deepEqual([update.disabled, restart.textContent, restart.disabled], [false, 'Restart', false]);
    assert.deepEqual(f.dialogs, [['alert', 'Command failed: HTTP 503']]);

    refusal = new TypeError('Failed to fetch');
    update.click();
    await settle();
    assert.deepEqual([update.textContent, update.disabled, restart.disabled], ['Update', false, false]);
    assert.deepEqual(f.dialogs[1], ['alert', 'Command failed: Failed to fetch']);
    assert.deepEqual(f.deployRequests().filter(r => r.startsWith('POST')),
        ['POST /api/nodes/edge-1/command', 'POST /api/nodes/edge-1/command']);
    await f.tick(5000);
    assert.equal(f.deployRequests().filter(r => r.startsWith('GET')).length, 1, 'a refused command reloads nothing');
});

test('after a refused command each of the node\'s buttons keeps its own label', async () => {
    const { update, restart } = await refusedCommand(() => response(503, {}));
    restart.click();
    await settle();
    assert.deepEqual([update.textContent, restart.textContent], ['Update', 'Restart']);
});

test('after a refused Update each button also keeps its own label', async () => {
    const { update, restart } = await refusedCommand(() => response(503, {}));
    update.click();
    await settle();
    assert.deepEqual([update.textContent, restart.textContent, update.disabled, restart.disabled], ['Update', 'Restart', false, false]);
});
