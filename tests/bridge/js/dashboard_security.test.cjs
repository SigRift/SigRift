/* The shipped dashboard (auth_guard.js + dashboard.js) booted in a parsed DOM:
 * authenticated requests, CSRF on writes, session expiry, sign-out, live
 * sockets and every untrusted string the Summary tab renders. */
const assert = require('node:assert/strict');
const test = require('node:test');
const { bootDashboard, response, injected, settle } = require('./untrusted_dom.cjs');

// Script-bearing markup: must only ever appear as text.
const MARKUP = '<img src=x onerror=alert(1)><script>alert(2)</script>';
// Breaks out of a double-quoted attribute unless quotes are escaped.
const QUOTE = 'x" onmouseover="alert(3)" data-x="';
const CSRF = 'csrf-abc123';

const IDS = ['connection-status', 'app-content',
    'user-info', 'span:user-display-name', 'span:user-role', 'button:settings-btn',
    'tbody:nodes-tbody', 'nodes-empty', 'node-count-badge', 'input:node-search', 'nodes-no-match',
    'alerts-list', 'alerts-empty', 'alert-count-badge', 'condition-rules-list', 'condition-rules-empty',
    'tbody:activity-log', 'activity-empty', 'critical-banner', 'critical-banner-msg',
    'tbody:active-freqs-tbody', 'active-freqs-badge', 'unique-freqs-grid', 'suspicious-freqs-list',
    'panel-raw-ingest-warning', 'tbody:raw-ingest-tbody', 'raw-ingest-badge',
    'canvas:floorplan-canvas', 'floorplan-tooltip', 'retry-box',
    'mfa-settings-overlay', 'mfa-loading', 'mfa-content', 'mfa-status-badge', 'mfa-enable-section',
    'mfa-enabled-section', 'mfa-setup-section', 'mfa-backup-count', 'button:mfa-enable-btn',
    'button:mfa-disable-btn', 'button:mfa-verify-setup-btn', 'button:mfa-regen-codes-btn',
    'input:mfa-verify-code', 'input:mfa-disable-code', 'mfa-setup-error', 'mfa-disable-error',
    'mfa-provisioning-uri', 'mfa-secret-display', 'mfa-backup-codes-display', 'mfa-regen-codes-display',
    'iq-capture-overlay', 'select:iq-capture-node-id', 'input:iq-capture-freq', 'input:iq-capture-duration',
    'input:iq-capture-samplerate', 'input:iq-capture-gain', 'iq-capture-status', 'button:iq-capture-submit'];

const dashboard = (options = {}) => bootDashboard({ ...options, ids: [...IDS, ...(options.ids || [])] });
const headerValues = call => Object.values(call.headers || {}).map(String);

test('a cookie session sends every call same-origin and keeps credentials out of URLs and auth headers', async () => {
    const f = dashboard({ routes: url => url.startsWith('/api/auth/me')
        ? { username: 'op', display_name: MARKUP, role: '<b>admin</b>' } : undefined });
    await settle();
    assert.ok(f.requests.length >= 10, 'the real boot path polls the API');
    for (const call of f.requests) {
        assert.equal(call.options.credentials, 'same-origin', call.url);
        assert.equal(call.headers.Authorization, undefined, call.url);
        assert.equal(call.headers['X-API-Key'], undefined, call.url);
        assert.doesNotMatch(call.url, /token|api_key|csrf/i);
    }
    assert.deepEqual(f.navigations, [], 'a CSRF cookie is a usable cookie session');
    // The signed-in account shows as text.
    assert.equal(f.el('user-display-name').textContent, MARKUP);
    assert.equal(f.el('user-display-name').children.length, 0);
    assert.equal(f.el('user-role').textContent, '(<b>admin</b>)');
    assert.equal(f.el('logout-btn').style.display, '');

    f.requests.length = 0;
    await f.db.apiFetch('/api/thing?x=1');
    assert.match(f.requests[0].url, /^\/api\/thing\?x=1&_t=\d+$/);
    await f.db.apiFetch('/api/thing', { method: 'POST', body: { a: '<b>"' } });
    assert.equal(f.requests[1].url, '/api/thing');
    assert.equal(f.requests[1].options.body, JSON.stringify({ a: '<b>"' }));
    assert.equal(f.requests[1].headers['Content-Type'], 'application/json');
});

test('a held session credential authenticates requests and sockets without ever entering a URL', async () => {
    const token = 'tok-' + 'S3cr3t'.repeat(6);
    const f = dashboard({ cookie: '', token });
    await settle();
    assert.deepEqual(f.navigations, []);
    assert.ok(f.requests.length >= 10);
    for (const call of f.requests) {
        assert.ok(headerValues(call).some(value => value.includes(token)), call.url);
        assert.ok(!call.url.includes(token), call.url);
    }
    assert.equal(f.sockets.length, 2);
    for (const socket of f.sockets) {
        assert.ok(!socket.url.includes(token));
        assert.ok([...socket.protocols].includes(token), 'the credential travels in the subprotocol header');
    }
});

test('a browser with no session is sent to sign-in and opens no live socket', async () => {
    const f = dashboard({ cookie: '' });
    await settle();
    assert.deepEqual(f.navigations, ['/login?next=%2F']);
    assert.equal(f.sockets.length, 0);
});

test('every mutating dashboard action carries the CSRF token; reads do not', async () => {
    // IDs with a space and a slash, so each path must encode the exact ID.
    const node = { node_id: 'edge 1', host: 'h', status: 'active', last_seen: new Date().toISOString(), capabilities: {} };
    const f = dashboard({ routes: (url, options) => {
        if (url.startsWith('/api/nodes/?')) return [node];
        if (/^\/api\/alerts\/\?_t=/.test(url)) return [{ alert_id: 'a/1', severity: 'warning', message: 'm', acknowledged: false }];
        if (url.startsWith('/api/alerts/rules/conditions?')) return [{ rule_id: 'r 1', name: 'R', conditions: [] }];
        return options.method && options.method !== 'GET' ? {} : undefined;
    } });
    await settle();
    f.answerConfirm(true);
    f.el('nodes-tbody').querySelector('[data-cmd-node]').click();
    f.el('alerts-list').querySelector('[data-ack-alert]').click();
    f.el('alerts-list').querySelector('[data-escalate-alert]').click();
    f.el('condition-rules-list').querySelector('[data-cr-delete]').click();
    await settle();
    assert.deepEqual(f.writes().map(call => [call.method, call.url.replace(/\?.*/, '')]), [
        ['POST', '/api/nodes/edge%201/command'], ['PUT', '/api/alerts/a%2F1/ack'],
        ['PUT', '/api/alerts/a%2F1/ack'], ['DELETE', '/api/alerts/rules/conditions/r%201']]);
    for (const call of f.writes()) assert.equal(call.headers['X-CSRF-Token'], CSRF, call.method + ' ' + call.url);
    for (const call of f.requests.filter(call => call.method === 'GET')) assert.equal(call.headers['X-CSRF-Token'], undefined);
    // A rule is deleted only after the operator confirms.
    f.answerConfirm(false);
    const before = f.writes().length;
    f.el('condition-rules-list').querySelector('[data-cr-delete]').click();
    await settle();
    assert.equal(f.writes().length, before);
});

test('an expired session (401) rejects as Unauthorized without connection-error toasts', async () => {
    let statusCode = 401;
    const f = dashboard({ routes: url => {
        if (url.startsWith('/api/status')) return response(statusCode, { detail: 'Session expired' });
        if (url.startsWith('/api/e204')) return response(204, null, '');
        if (url.startsWith('/api/csv')) return response(200, 'a,b', 'text/csv');
        if (url.startsWith('/api/oops')) return response(500, 'not json', 'text/plain');
        return undefined;
    } });
    await settle();
    await assert.rejects(f.db.apiFetch('/api/status'), { message: 'Unauthorized' });
    const polls = () => f.requests.filter(call => call.url.startsWith('/api/status?')).length;
    // A minute of background polling against the expired session.
    let before = polls();
    await f.tick(60000);
    assert.ok(polls() - before >= 3, 'the status poll kept running');
    assert.ok(!f.toasts().some(text => /Connection issue/.test(text)), '401s are not network failures');
    // The same counter does report a persistently failing source, once.
    statusCode = 503;
    before = polls();
    await f.tick(60000);
    assert.ok(polls() - before >= 3);
    assert.deepEqual(f.toasts().filter(text => /Connection issue/.test(text)), ['Connection issue: status failing']);
    assert.equal(await f.db.apiFetch('/api/e204'), null);
    assert.equal((await f.db.apiFetch('/api/csv')).status, 200);
    await assert.rejects(f.db.apiFetch('/api/oops'), { message: 'HTTP 500' });
});

test('an expired session (401) returns the operator to sign-in', async () => {
    const f = dashboard({ routes: url => url.startsWith('/api/') && !url.startsWith('/api/auth/me')
        ? response(401, { detail: 'Session expired' }) : undefined });
    await settle();
    assert.ok(f.navigations.some(url => url.startsWith('/login')), JSON.stringify(f.navigations));
});

test('a session ended elsewhere (401 on any call) signs this tab out once and forgets its stored credential', async () => {
    const token = 'tok-' + 'E'.repeat(40);
    let ended = false;
    const f = dashboard({ cookie: '', token, routes: url => (ended && url.startsWith('/api/')
        ? response(401, { detail: 'Session expired' }) : undefined) });
    await settle();
    assert.deepEqual(f.navigations, [], 'a live session stays on the dashboard');
    ended = true;
    // An operator action refused because the session ended, then a minute of polls.
    await assert.rejects(f.db.apiFetch('/api/nodes/edge-1/command', { method: 'POST', body: { command: 'restart' } }),
        error => error.message === 'Unauthorized' && error.status === 401 && error.detail === 'Session expired');
    await f.tick(60000);
    assert.deepEqual(f.navigations, ['/login?next=%2F'], 'one sign-in navigation that returns to this page');
    assert.equal(f.context.sessionStorage.getItem('bridge_session_token'), null, 'the refused token is not kept for a reload');
});

test('a wrong MFA code (401) shows the server reason and keeps the operator signed in', async () => {
    const f = dashboard({ routes: url => {
        if (url.startsWith('/api/auth/me')) return { username: 'op', mfa_enabled: true, backup_codes_remaining: 3 };
        if (url === '/api/auth/mfa/verify-setup') return response(401, { detail: 'Invalid TOTP code. Check your authenticator app and try again.' });
        if (url === '/api/auth/mfa/disable') return response(401, { detail: 'TOTP code already used. Wait for a new code.' });
        if (url === '/api/auth/mfa/regenerate-backup-codes') return response(401, { detail: 'Invalid TOTP code' });
        return undefined;
    } });
    await settle();
    f.el('settings-btn').click();
    await settle();
    f.el('mfa-verify-code').value = '123456';
    f.el('mfa-verify-setup-btn').click();
    await settle();
    assert.equal(f.el('mfa-setup-error').textContent, 'Invalid TOTP code. Check your authenticator app and try again.');
    f.answerConfirm(true);
    f.el('mfa-disable-code').value = '654321';
    f.el('mfa-disable-btn').click();
    await settle();
    assert.equal(f.el('mfa-disable-error').textContent, 'TOTP code already used. Wait for a new code.');
    f.answerPrompt('111111');
    f.el('mfa-regen-codes-btn').click();
    await settle();
    assert.equal(f.el('mfa-disable-error').textContent, 'Invalid TOTP code');
    assert.deepEqual(f.writes().map(call => call.url), ['/api/auth/mfa/verify-setup', '/api/auth/mfa/disable', '/api/auth/mfa/regenerate-backup-codes']);
    assert.deepEqual(f.navigations, [], 'a mistyped code is not an ended session');
});

test('a 401 never writes credential material to the console', async () => {
    const token = 'tok-ZXCVBNMASDFGHJKL0123456789';
    const f = dashboard({ cookie: '', token, routes: url => url.startsWith('/api/status') ? response(401, {}) : undefined });
    await settle();
    await assert.rejects(f.db.apiFetch('/api/status'), { message: 'Unauthorized' });
    for (const line of f.warnings) assert.ok(!line.includes(token.slice(0, 8)), line);
});

test('a JSON error body keeps its detail for the caller', async () => {
    const f = dashboard({ routes: url => url.startsWith('/api/bad') ? response(422, { detail: 'Code already used' }) : undefined });
    await settle();
    await assert.rejects(f.db.apiFetch('/api/bad', { method: 'POST' }), error => error.detail === 'Code already used');
});

test('every failed response keeps its status; only a string detail is passed on', async () => {
    const f = dashboard({ routes: url => {
        if (url.startsWith('/api/conflict')) return response(409, { detail: MARKUP });
        if (url.startsWith('/api/invalid')) return response(422, { detail: [{ loc: ['body', 'ids'], msg: 'field required' }] });
        if (url.startsWith('/api/gateway')) return response(502, '<html>Bad gateway</html>', 'text/html');
        if (url.startsWith('/api/empty')) return response(503, null, '');
        return undefined;
    } });
    await settle();
    const failure = path => f.db.apiFetch(path).then(() => assert.fail(path + ' resolved'), error => error);
    const shape = error => [error instanceof f.context.Error, error.message, error.status, error.detail];
    assert.deepEqual(shape(await failure('/api/conflict')), [true, 'HTTP 409', 409, MARKUP]);
    assert.deepEqual(shape(await failure('/api/invalid')), [true, 'HTTP 422', 422, undefined]);
    assert.deepEqual(shape(await failure('/api/gateway')), [true, 'HTTP 502', 502, undefined]);
    assert.deepEqual(shape(await failure('/api/empty')), [true, 'HTTP 503', 503, undefined]);
    assert.deepEqual(f.navigations, []);
});

test('cookie-session sockets carry no credential and reconnect with bounded backoff', async () => {
    const f = dashboard();
    await settle();
    assert.deepEqual(f.sockets.map(socket => [socket.url, [...socket.protocols]]), [
        ['wss://bridge.test/api/nodes/ws/status', []], ['wss://bridge.test/api/alerts/ws/alerts', []]]);
    const status = f.sockets[0];
    status.open();
    assert.equal(f.el('connection-status').className, 'connection-indicator connected');
    const delays = [];
    let socket = status;
    for (let attempt = 0; attempt < 6; attempt++) {
        const timersBefore = f.timers.length, socketsBefore = f.sockets.length;
        socket.onerror();                       // an error closes and schedules a reconnect
        const retry = f.timers.slice(timersBefore).find(timer => !timer.repeat);
        if (!retry) break;
        delays.push(retry.delay);
        retry.callback();
        if (f.sockets.length === socketsBefore) break;
        socket = f.sockets.at(-1);
    }
    assert.deepEqual(delays, [2000, 4000, 8000, 16000, 30000], 'exponential, capped, and finite');
    assert.equal(f.sockets.filter(s => s.url.endsWith('/ws/status')).length, 5, 'gives up after five retries');
    assert.equal(f.el('connection-status').className, 'connection-indicator disconnected');
});

test('live status snapshots update the node table; malformed or hostile frames change nothing or stay text', async () => {
    const f = dashboard({ ids: ['canvas:threat-timeline-canvas', 'threat-timeline-summary'] });
    await settle();
    const [status, alerts] = f.sockets;
    status.open(); alerts.open();
    const rows = () => f.el('nodes-tbody').querySelectorAll('[data-cmd-node]').map(button => button.getAttribute('data-cmd-node'));
    assert.deepEqual(rows(), []);
    // A snapshot pushed after the boot-time HTTP poll replaces the node table.
    f.advance(1000);
    status.message({ type: 'snapshot', nodes: [{ node_id: 'edge-ws', host: MARKUP, status: 'active', capabilities: {},
        scanner_status: { sdr: { protocol: 'sdr', state: 'running', active: true, expires_in_seconds: 60, reported_at: new Date().toISOString() } } }] });
    assert.deepEqual(rows(), ['edge-ws']);
    assert.equal(f.el('node-count-badge').textContent, '1');
    assert.equal(f.el('nodes-tbody').querySelector('.status-radio').textContent, 'SDR scanning');
    assert.ok(f.el('nodes-tbody').textContent.includes(MARKUP));
    alerts.message({ alert_id: 'a-9', severity: 'critical', name: MARKUP, node_id: 'edge-<b>1</b>',
        message: 'Rogue &lt;img src=x onerror=alert(1)&gt; AP' });
    await settle();
    const literal = 'Rogue <img src=x onerror=alert(1)> AP';
    assert.ok(f.toasts().includes(literal), JSON.stringify(f.toasts()));
    assert.equal(f.el('critical-banner-msg').textContent, literal);
    assert.match(f.document.title, /^\(1\) /);
    // The threat timeline shows the alert as text and opens exactly that alert.
    const focused = [];
    f.db.alertsDashboard = { focusAlert: id => focused.push(id) };
    const canvas = f.el('threat-timeline-canvas'), summary = f.el('threat-timeline-summary');
    canvas.dispatchEvent(new f.context.Event('focus'));
    assert.equal(summary.hidden, false);
    assert.match(summary.textContent, /^Alert · critical · /);
    assert.ok(summary.textContent.endsWith(' · ' + literal + ' — Click or press Enter to open Alerts.'), summary.textContent);
    assert.equal(summary.children.length, 0);
    canvas.dispatchEvent(new f.context.Event('keydown', { key: 'Enter' }));
    assert.deepEqual(focused, ['a-9']);
    for (const frame of ['not json', '{"type":', 'null', '[]', '"text"', '42', '{"type":"snapshot","nodes":"x"}',
        '{"type":"snapshot"}', '{"type":"snapshot","nodes":{"0":{"node_id":"edge-x"}}}']) {
        assert.doesNotThrow(() => status.message(frame));
        assert.doesNotThrow(() => alerts.message(frame));
    }
    assert.deepEqual(rows(), ['edge-ws'], 'a malformed snapshot neither blanks nor replaces the table');
    assert.deepEqual(injected(f.document.body), []);
});

test('critical alert bursts coalesce by name as text, mark repeats, and clear on dismiss', async () => {
    const f = dashboard({ ids: ['button:critical-banner-dismiss'] });
    await settle();
    const alerts = f.sockets[1];
    alerts.open();
    alerts.message({ alert_id: 'a-1', severity: 'critical', name: MARKUP, node_id: 'edge-1', message: 'first' });
    alerts.message({ alert_id: 'a-2', severity: 'critical', name: MARKUP, node_id: 'edge-2', message: 'second' });
    alerts.message({ alert_id: 'a-3', severity: 'critical', name: 'Solo', message: 'Solo &lt;b&gt;' });
    alerts.message({ alert_id: 'a-4', severity: 'warning', name: 'Quiet', message: 'not a banner' });
    const banner = f.el('critical-banner'), text = f.el('critical-banner-msg');
    assert.equal(text.textContent, `${MARKUP} × 2 (2 nodes) — Solo <b>`);
    assert.equal(text.children.length, 0);
    assert.equal(f.document.title, '(3) SigRift — Critical Alert');
    assert.ok(!banner.classList.contains('critical-banner-repeat'));
    // The same alert firing again is coalesced and marked as already seen.
    alerts.message({ alert_id: 'a-1', severity: 'critical', name: MARKUP, node_id: 'edge-1', message: 'again' });
    const coalesced = `${MARKUP} × 3 (2 nodes) — Solo <b>`;
    assert.equal(text.textContent.slice(0, coalesced.length), coalesced);
    assert.match(text.textContent.slice(coalesced.length), /^ \(seen \d+s ago\)$/);
    assert.ok(banner.classList.contains('critical-banner-repeat'));
    assert.deepEqual(injected(banner), []);
    f.el('critical-banner-dismiss').click();
    assert.ok(banner.classList.contains('hidden'));
    assert.equal(f.document.title, 'SigRift');
});

test('node fields render as literal text and node controls address the exact node', async () => {
    const node = { node_id: 'edge-1', host: MARKUP, status: 'active', last_seen: new Date().toISOString(),
        cpu_percent: 12.5, memory_mb: 512, position_x: 50, position_y: 50, floor_label: MARKUP,
        capabilities: { agent_version: MARKUP, gpu: 'Jetson & <Coral>', last_error: MARKUP, hardware: 'RTL-SDR <v3>', capture_mode: 'dual' },
        detection_summary: { total_detections: 10, period_seconds: 60, class_counts: { [MARKUP]: 3, fm: 5 } } };
    const f = dashboard({ routes: (url, options) => url.startsWith('/api/nodes/?') ? [node]
        : options.method === 'POST' ? {} : undefined });
    await settle();
    const tbody = f.el('nodes-tbody');
    assert.equal(tbody.querySelectorAll('tr').length, 1);
    assert.deepEqual(injected(tbody), []);
    for (const text of [MARKUP, 'v' + MARKUP, 'RTL-SDR <v3>', 'Jetson & <Coral>']) assert.ok(tbody.textContent.includes(text), text);
    assert.equal(tbody.querySelector('.node-top-issue').textContent, '\u2716' + MARKUP.substring(0, 33) + '..');
    assert.ok(tbody.querySelectorAll('.node-class-bar').some(bar => bar.getAttribute('title') === MARKUP + ': 3'));
    assert.equal(tbody.querySelector('.node-status-compact').getAttribute('title'), 'Hardware: RTL-SDR <v3>');

    tbody.querySelector('[data-cmd-node]').click();
    await settle();
    assert.equal(f.lastWrite().url, '/api/nodes/edge-1/command');
    assert.deepEqual(f.body(f.lastWrite()), { command: 'ping', params: {} });

    // Search matches the text the operator sees, never the table's own markup.
    const search = f.el('node-search');
    const shown = term => {
        search.value = term;
        search.dispatchEvent(new f.context.Event('input'));
        return tbody.querySelector('tr').style.display === '';
    };
    assert.equal(shown('<IMG SRC'), true);
    assert.equal(shown('jetson & <coral>'), true, 'text with & and < is matched as typed');
    assert.equal(f.el('nodes-no-match').style.display, 'none');
    for (const markupOnly of ['no such node', 'data-cmd-node', 'node-col-detail', '&lt;', '&amp;']) {
        assert.equal(shown(markupOnly), false, markupOnly);
    }
    assert.equal(f.el('nodes-no-match').style.display, '');
    assert.equal(shown(''), true);

    // Floor plan hover tooltip at the node's plotted position.
    f.el('floorplan-canvas').dispatchEvent(new f.context.Event('mousemove', { clientX: 150, clientY: 75 }));
    const tooltip = f.el('floorplan-tooltip');
    assert.equal(tooltip.style.display, '');
    assert.ok(tooltip.textContent.includes('Host: ' + MARKUP));
    assert.ok(tooltip.textContent.includes('Floor: ' + MARKUP));
    assert.deepEqual(injected(tooltip), []);
});

// Both values come from POST /api/nodes/heartbeat, which a node's own SENSOR
// key sends: NodeMetrics allows extra fields (copied into capabilities.hardware)
// and DetectionSummary.class_counts keys are free text.
test('heartbeat-reported strings cannot break out of node table attributes', async () => {
    const node = { node_id: 'edge-1', host: 'h', status: 'active', capabilities: { hardware: QUOTE },
        detection_summary: { total_detections: 1, period_seconds: 60, class_counts: { [QUOTE]: 1 } } };
    const f = dashboard({ routes: url => url.startsWith('/api/nodes/?') ? [node] : undefined });
    await settle();
    const tbody = f.el('nodes-tbody');
    assert.deepEqual(injected(tbody), []);
    assert.equal(tbody.querySelector('.node-status-compact').getAttribute('title'), 'Hardware: ' + QUOTE);
    assert.equal(tbody.querySelector('.node-class-bar').getAttribute('title'), QUOTE + ': 1');
});

test('one malformed heartbeat value does not blank the whole node table', async () => {
    const good = { node_id: 'edge-1', host: 'h', status: 'active', capabilities: { cpu_temp: 40 } };
    const bad = { node_id: 'edge-2', host: 'h', status: 'active', capabilities: { cpu_temp: 'hot' } };
    const f = dashboard({ routes: url => url.startsWith('/api/nodes/?') ? [good, bad] : undefined });
    await settle();
    assert.equal(f.el('nodes-tbody').querySelectorAll('[data-cmd-node]').length, 2);
});

// Older bridges stored heartbeat values unchecked, and admin-registered
// capabilities are free-form: every number the row formats is read as not
// reported when it is not a finite number.
test('node values of another type read as not reported, and the other nodes still render', async () => {
    const odd = { node_id: 'edge-2', host: 'h', status: 'active', cpu_percent: '95', memory_mb: [512],
        classifications_per_sec: 'fast', detection_summary: { total_detections: '10', period_seconds: {} },
        capabilities: { cpu_temp: { celsius: 90 }, uptime_seconds: 'long', heartbeat_latency_ms: '900', last_error: 42 } };
    const good = { node_id: 'edge-1', host: 'h', status: 'active', cpu_percent: 80, memory_mb: 512,
        capabilities: { cpu_temp: 40, uptime_seconds: 7260, heartbeat_latency_ms: 250 } };
    const f = dashboard({ routes: url => url.startsWith('/api/nodes/?') ? [odd, good] : undefined });
    await settle();
    const [row, other] = f.el('nodes-tbody').querySelectorAll('tr');
    const detail = tr => tr.querySelectorAll('td.node-col-detail').slice(-5).map(td => td.textContent);
    assert.deepEqual(detail(row), ['--', '--', '--', '--', '--'], 'uptime, CPU, memory, temperature, latency');
    assert.deepEqual(detail(other), ['2h 1m', '80.0', '512', '40°C', '250ms']);
    assert.equal(row.querySelectorAll('td')[4].textContent, '--', 'detections per minute');
    assert.equal(row.querySelector('.node-top-issue').textContent, '✖42');
    assert.equal(row.querySelector('.node-health').textContent.trim(), 'Online');
    assert.equal(other.querySelector('.node-health').textContent.trim(), 'Degraded');
    assert.doesNotMatch(row.textContent, /NaN|undefined|object/);
});

test('a long last_error that is not text is shown as text, and the other nodes still render', async () => {
    // An array has a length but no substring(): it is read through String().
    const odd = { node_id: 'edge-2', host: 'h', status: 'active',
        capabilities: { last_error: Array.from({ length: 31 }, () => 'e') } };
    const good = { node_id: 'edge-1', host: 'h', status: 'active', capabilities: {} };
    const f = dashboard({ routes: url => url.startsWith('/api/nodes/?') ? [odd, good] : undefined });
    await settle();
    const rows = f.el('nodes-tbody').querySelectorAll('tr');
    assert.equal(rows.length, 2);
    const text = Array(31).fill('e').join(',');
    assert.equal(rows[0].querySelector('.node-top-issue').textContent, '✖' + text.substring(0, 33) + '..');
    assert.equal(rows[1].querySelector('.node-top-issue').textContent, 'No issues reported');
});

test('detection summary numbers of another type read as not reported', async () => {
    // Detections per minute: total / period * 60 only from two numbers.
    const node = (node_id, detection_summary) => ({ node_id, host: 'h', status: 'active', detection_summary });
    const nodes = [
        node('text-both', { total_detections: '10', period_seconds: '60' }),
        node('text-total', { total_detections: '10', period_seconds: 60 }),
        node('text-period', { total_detections: 10, period_seconds: '60' }),
        node('numbers', { total_detections: 10, period_seconds: 60 }),
    ];
    const f = dashboard({ routes: url => url.startsWith('/api/nodes/?') ? nodes : undefined });
    await settle();
    const rates = f.el('nodes-tbody').querySelectorAll('tr').map(tr => tr.querySelectorAll('td')[4].textContent);
    assert.deepEqual(rates, ['--', '0.0', '--', '10.0']);
});

test('Summary alerts decode stored text once and acknowledge the exact alert with the operator note', async () => {
    const now = Date.now();
    const list = [
        { alert_id: 'a-1', severity: 'critical', message: 'Rogue &lt;img src=x onerror=alert(1)&gt; &amp;amp; AP',
            triggered_at: new Date(now - 60000).toISOString(), acknowledged: false, rf_detection_id: 'det <b>1</b> &amp;' },
        { alert_id: 'a-2', severity: 'warning', message: 'done', acknowledged: true, acknowledged_by: MARKUP,
            triggered_at: new Date(now - 120000).toISOString(), acknowledged_at: new Date(now - 60000).toISOString(),
            ack_note: 'seen &lt;b&gt;' },
        { alert_id: 'a-3', severity: 'info', message: 'third', triggered_at: new Date(now - 30000).toISOString(), acknowledged: false }];
    let ackStatus = 200;
    const f = dashboard({ ids: ['input:alert-hide-acked'], routes: (url, options) => {
        if (/^\/api\/alerts\/\?_t=/.test(url)) return list;
        if (options.method === 'PUT') return response(ackStatus, {});
        return undefined;
    } });
    await settle();
    const container = f.el('alerts-list');
    assert.deepEqual(container.querySelectorAll('.alert-msg').map(el => el.textContent),
        ['Rogue <img src=x onerror=alert(1)> &amp; AP', 'done', 'third']);
    assert.equal(container.querySelector('.ack-user').textContent, MARKUP);
    assert.equal(container.querySelector('.ack-note').textContent, '"seen <b>"');
    assert.equal(container.querySelector('.ack-tta').textContent, '(TTA: 1m)');
    assert.equal(container.querySelector('[data-known-detection]').getAttribute('data-known-detection'), 'det <b>1</b> &amp;');
    assert.deepEqual(injected(container), []);
    // Hiding acknowledged alerts leaves exactly the open one.
    const hide = f.el('alert-hide-acked');
    hide.checked = true;
    hide.dispatchEvent(new f.context.Event('change'));
    await settle();
    assert.deepEqual(container.querySelectorAll('.alert-msg').map(el => el.textContent), ['Rogue <img src=x onerror=alert(1)> &amp; AP', 'third']);
    assert.equal(f.el('alert-count-badge').textContent, '2');
    hide.checked = false;

    // Each open alert has its own note; acknowledging one sends only its note.
    container.querySelector('[data-ack-note-for="a-1"]').value = 'note for the first';
    container.querySelector('[data-ack-note-for="a-3"]').value = '  checked <ok> ';
    container.querySelector('[data-ack-alert="a-3"]').click();
    await settle();
    assert.equal(f.lastWrite().url, '/api/alerts/a-3/ack');
    assert.deepEqual(f.body(f.lastWrite()), { note: 'checked <ok>' });
    assert.ok(f.toasts().includes('Alert acknowledged'));
    // A blank note is not sent.
    container.querySelector('[data-ack-note-for="a-1"]').value = '   ';
    container.querySelector('[data-ack-alert="a-1"]').click();
    await settle();
    assert.equal(f.lastWrite().url, '/api/alerts/a-1/ack');
    assert.equal(f.lastWrite().options.body, undefined);

    f.el('alerts-list').querySelector('[data-escalate-alert]').click();
    await settle();
    assert.deepEqual(f.body(f.lastWrite()), { note: 'ESCALATED', escalated: true });
    ackStatus = 500;
    f.el('alerts-list').querySelector('[data-ack-alert]').click();
    await settle();
    assert.ok(f.toasts().includes('Failed to acknowledge alert'));
});

// Alert IDs are server-generated, but rf_detection_id is a sensor
// detection_id that the bridge ingest does not validate.
test('alert and detection IDs cannot break out of the Summary alert attributes', async () => {
    const f = dashboard({ routes: url => /^\/api\/alerts\/\?_t=/.test(url)
        ? [{ alert_id: QUOTE, severity: 'warning', message: 'm', acknowledged: false, rf_detection_id: QUOTE }] : undefined });
    await settle();
    const list = f.el('alerts-list');
    assert.deepEqual(injected(list), []);
    assert.equal(list.querySelector('[data-ack-alert]').getAttribute('data-ack-alert'), QUOTE);
    assert.equal(list.querySelector('[data-known-detection]').getAttribute('data-known-detection'), QUOTE);
});

test('alert rules show stored names and hostile condition values as text', async () => {
    const rule = { rule_id: 'r/1 x', name: 'Rule &lt;script&gt;alert(1)&lt;/script&gt;', severity: 'warning', enabled: false,
        cooldown_seconds: '<b>60</b>', trigger_count: 2, logic: '<i>AND</i>',
        conditions: [{ field: 'signal_class', operator: 'in', value: ['<img src=x onerror=1>', 'fm'] },
            { field: 'power_dbm', operator: 'between', value: [-50, -10] }, { field: MARKUP, operator: MARKUP, value: MARKUP }] };
    const f = dashboard({ routes: (url, options) => url.startsWith('/api/alerts/rules/conditions?') ? [rule]
        : options.method === 'DELETE' ? {} : undefined });
    await settle();
    const list = f.el('condition-rules-list');
    assert.equal(list.querySelector('.cr-name').textContent, 'Rule <script>alert(1)</script>');
    const summary = list.querySelector('.cr-conditions-summary').textContent;
    assert.ok(summary.includes('signal_class in [<img src=x onerror=1>, fm]'), summary);
    assert.ok(summary.includes('power_dbm between -50 .. -10'), summary);
    assert.ok(summary.includes(`${MARKUP} ${MARKUP} ${MARKUP}`), summary);
    assert.ok(list.textContent.includes('Cooldown: <b>60</b>s'));
    assert.ok(list.textContent.includes('[disabled]'));
    assert.deepEqual(injected(list), []);
    f.answerConfirm(true);
    list.querySelector('[data-cr-delete]').click();
    await settle();
    assert.equal(f.lastWrite().method, 'DELETE');
    assert.equal(f.lastWrite().url, '/api/alerts/rules/conditions/r%2F1%20x');
    assert.equal(f.lastWrite().headers['X-CSRF-Token'], CSRF);
    assert.ok(f.toasts().includes('Rule deleted'));
});

test('editing a stored rule decodes its name once into the form and saves exactly that rule', async () => {
    const rule = { rule_id: 'r 1', name: 'Rule &lt;script&gt;alert(1)&lt;/script&gt; &amp;amp;', severity: 'critical', logic: 'OR',
        cooldown_seconds: 60, enabled: false, conditions: [{ field: 'signal_class', operator: 'in', value: ['<img src=x onerror=1>', 'fm'] },
            { field: 'power_dbm', operator: 'between', value: [-50, -10] }] };
    const f = dashboard({
        ids: ['cb-title', 'input:cb-rule-name', 'select:cb-rule-severity', 'select:cb-rule-logic', 'input:cb-cooldown',
            'input:cb-enabled', 'input:cb-editing-rule-id', 'cb-conditions', 'cb-no-conditions', 'button:cb-save-rule', 'cb-test-result'],
        routes: (url, options) => url.startsWith('/api/alerts/rules/conditions?') ? [rule]
            : options.method === 'PUT' ? {} : undefined });
    await settle();
    f.el('condition-rules-list').querySelector('[data-cr-edit]').click();
    const decoded = 'Rule <script>alert(1)</script> &amp;';
    assert.equal(f.el('cb-title').textContent, 'Edit Rule: ' + decoded);
    assert.equal(f.el('cb-rule-name').value, decoded);
    const rows = f.el('cb-conditions').querySelectorAll('.cb-condition-row');
    assert.deepEqual(rows.map(row => row.querySelector('.cb-value-input').value), ['<img src=x onerror=1>, fm', '-50']);
    assert.equal(rows[1].querySelector('.cb-value2-input').value, '-10');
    assert.deepEqual(injected(f.el('cb-conditions')), []);
    assert.deepEqual(injected(f.el('cb-title')), []);

    f.el('cb-save-rule').click();
    await settle();
    const call = f.lastWrite();
    assert.equal(call.method, 'PUT');
    assert.equal(call.url, '/api/alerts/rules/conditions/r%201');
    assert.equal(call.headers['X-CSRF-Token'], CSRF);
    assert.deepEqual(f.body(call), { name: decoded, severity: 'critical', logic: 'OR', cooldown_seconds: 60, enabled: false,
        notify_webhook: true, conditions: [{ field: 'signal_class', operator: 'in', value: ['<img src=x onerror=1>', 'fm'] },
            { field: 'power_dbm', operator: 'between', value: [-50, -10] }] });
    assert.ok(f.toasts().includes('Rule updated'));
    assert.equal(f.el('cb-editing-rule-id').value, '', 'the form no longer targets the saved rule');

    // An incomplete rule is never sent.
    const count = f.writes().length;
    f.el('cb-save-rule').click();
    f.el('cb-rule-name').value = 'named';
    f.el('cb-save-rule').click();
    assert.equal(f.writes().length, count);
    assert.ok(f.toasts().includes('Rule name is required') && f.toasts().includes('Add at least one condition'));
});

test('activity, ingest and frequency panels render node and signal strings as text', async () => {
    const freqs = [
        { freq_mhz: 433.92, count: 1, classes: '<img src=x onerror=1>,fm', nodes: 'edge-<b>1</b>', avg_power_dbm: -10 },
        { freq_mhz: 100.1, count: 40, classes: 'fm', nodes: 'a,b', avg_power_dbm: -60 },
        { freq_mhz: 300, count: 40, classes: 'mil', nodes: 'a,b', avg_power_dbm: -61 },
        { freq_mhz: 9000, count: 40, classes: 'x', nodes: 'a,b', avg_power_dbm: -62 }];
    const f = dashboard({ routes: url => {
        if (url.startsWith('/api/nodes/activity')) return [{ timestamp: new Date().toISOString(), node_id: MARKUP, event_type: '<b>t</b>', message: MARKUP }];
        if (url.startsWith('/api/detections/ingest-status')) return { raw_ingest_nodes: { [MARKUP]: 1700000000, migrated: 5 }, summary_ingest_nodes: { migrated: 6 } };
        if (url.startsWith('/api/status')) return { node_count: 1, active_frequency_list: freqs };
        return undefined;
    } });
    await settle();
    const activity = f.el('activity-log');
    assert.equal(activity.querySelector('.activity-node').textContent, MARKUP);
    assert.equal(activity.querySelector('.activity-type').textContent, '<b>t</b>');
    const ingest = f.el('raw-ingest-tbody');
    assert.equal(ingest.querySelectorAll('tr').length, 1, 'a node that migrated to summaries is not listed');
    assert.equal(ingest.querySelector('td').textContent, MARKUP);
    const active = f.el('active-freqs-tbody');
    assert.ok(active.querySelectorAll('[data-drilldown-summary-class]').some(tag => tag.getAttribute('data-drilldown-summary-class') === '<img src=x onerror=1>'));
    assert.ok(active.textContent.includes('edge-<b>1</b>'));
    const suspicious = f.el('suspicious-freqs-list');
    assert.ok(suspicious.textContent.includes('Single-node sighting (edge-<b>1</b>)'), suspicious.textContent);
    assert.ok(suspicious.textContent.includes('Military band activity'));
    for (const panel of [activity, ingest, active, suspicious, f.el('unique-freqs-grid')]) assert.deepEqual(injected(panel), []);
});

test('sign-out revokes the server session first, then clears credentials and stops live sockets', async () => {
    let finish;
    const f = dashboard({ routes: url => url === '/api/auth/logout' ? new Promise(resolve => { finish = resolve; }) : undefined });
    await settle();
    f.sockets.forEach(socket => socket.open());
    const button = f.el('logout-btn');
    button.click();
    button.disabled = false; button.click();   // a second click while pending
    const logouts = f.requests.filter(call => call.url === '/api/auth/logout');
    assert.equal(logouts.length, 1);
    assert.equal(logouts[0].method, 'POST');
    assert.equal(logouts[0].headers['X-CSRF-Token'], CSRF);
    assert.equal(logouts[0].options.credentials, 'same-origin');
    assert.ok(f.sockets.every(socket => !socket.closed), 'sockets stay up until the server confirms');
    assert.deepEqual(f.navigations, []);
    finish(response(200, {}));
    await settle();
    assert.ok(f.sockets.every(socket => socket.closed));
    assert.deepEqual(f.navigations, ['/login']);
    const sockets = f.sockets.length;
    f.runTimers(timer => !timer.repeat);
    assert.equal(f.sockets.length, sockets, 'no socket reconnects after sign-out');
    // The server expires its cookies; nothing in the browser can resume the session.
    f.document.cookie = '';
    f.load('auth_guard.js');
    assert.deepEqual(f.navigations, ['/login', '/login?next=%2F']);
});

test('sign-out of a held session credential leaves nothing a reload could reuse', async () => {
    const token = 'tok-' + 'Q'.repeat(40);
    const f = dashboard({ cookie: '', token, routes: url => url === '/api/auth/logout' ? {} : undefined });
    await settle();
    f.el('logout-btn').click();
    await settle();
    const logout = f.requests.find(call => call.url === '/api/auth/logout');
    assert.ok(headerValues(logout).some(value => value.includes(token)), 'the revocation is authenticated');
    assert.deepEqual(f.navigations, ['/login']);
    await f.db.apiFetch('/api/after');
    assert.ok(!headerValues(f.requests.at(-1)).some(value => value.includes(token)));
    f.load('auth_guard.js');
    assert.deepEqual(f.navigations, ['/login', '/login?next=%2F']);
});

for (const failure of ['server error', 'network error']) {
    test(`a failed sign-out (${failure}) stays signed in and says so; an expired session signs out`, async () => {
        let answer = failure === 'server error' ? response(500, {}) : new Error('offline');
        const f = dashboard({ routes: url => url === '/api/auth/logout' ? answer : undefined });
        await settle();
        f.sockets.forEach(socket => socket.open());
        f.el('logout-btn').click();
        await settle();
        assert.deepEqual(f.navigations, []);
        assert.equal(f.el('logout-btn').disabled, false);
        assert.ok(f.sockets.every(socket => !socket.closed));
        assert.ok(f.toasts().includes('Could not sign out. Please try again.'));
        answer = response(401, {});
        f.el('logout-btn').click();
        await settle();
        assert.deepEqual(f.navigations, ['/login']);
    });
}

test('MFA settings show secrets and backup codes as text and send codes only when complete and confirmed', async () => {
    const f = dashboard({ routes: (url, options) => {
        if (url.startsWith('/api/auth/me')) return { username: 'op', mfa_enabled: false, backup_codes_remaining: 3 };
        if (url === '/api/auth/mfa/setup') return { provisioning_uri: 'otpauth://totp/SigRift:op?secret=ABC&issuer=<b>x</b>',
            secret: 'ABC<b>', backup_codes: [MARKUP, 'CODE-2'] };
        // A refusal without a reason (the reason-dropping BUG is tested above).
        if (url === '/api/auth/mfa/verify-setup') return response(400, {});
        if (url === '/api/auth/mfa/regenerate-backup-codes') return { backup_codes: ['<i>N1</i>'], backup_codes_remaining: 1 };
        return options.method === 'POST' ? {} : undefined;
    } });
    await settle();
    f.el('settings-btn').click();
    await settle();
    assert.equal(f.el('mfa-status-badge').textContent, 'Disabled');
    assert.equal(f.el('mfa-backup-count').textContent, '3');
    f.el('mfa-enable-btn').click();
    await settle();
    assert.equal(f.lastWrite().url, '/api/auth/mfa/setup');
    assert.equal(f.lastWrite().headers['X-CSRF-Token'], CSRF);
    assert.equal(f.el('mfa-secret-display').textContent, 'ABC<b>');
    assert.equal(f.el('mfa-provisioning-uri').textContent, 'otpauth://totp/SigRift:op?secret=ABC&issuer=<b>x</b>');
    const codes = f.el('mfa-backup-codes-display');
    assert.deepEqual(codes.children.map(child => child.textContent), [MARKUP, 'CODE-2']);
    assert.deepEqual(injected(f.el('mfa-settings-overlay').parentNode), []);
    assert.equal(f.document.activeElement, f.el('mfa-verify-code'));

    const writes = () => f.writes().length;
    let count = writes();
    f.el('mfa-verify-code').value = '12345';
    f.el('mfa-verify-setup-btn').click();
    assert.equal(writes(), count, 'an incomplete TOTP code is not sent');
    assert.equal(f.el('mfa-setup-error').textContent, 'Enter a 6-digit code.');
    f.el('mfa-verify-code').value = ' 123456 ';
    f.el('mfa-verify-setup-btn').click();
    await settle();
    assert.equal(f.lastWrite().url, '/api/auth/mfa/verify-setup');
    assert.deepEqual(f.body(f.lastWrite()), { totp_code: '123456' });
    assert.equal(f.el('mfa-setup-error').textContent, 'Verification failed. Try again.');
    assert.equal(f.el('mfa-verify-setup-btn').disabled, false, 'the operator can retry');

    count = writes();
    f.el('mfa-disable-code').value = '';
    f.el('mfa-disable-btn').click();
    assert.equal(f.el('mfa-disable-error').textContent, 'Enter a TOTP code to confirm.');
    f.el('mfa-disable-code').value = '654321';
    f.answerConfirm(false);
    f.el('mfa-disable-btn').click();
    assert.equal(writes(), count, 'disabling MFA needs explicit confirmation');
    f.answerConfirm(true);
    f.el('mfa-disable-btn').click();
    await settle();
    assert.equal(f.lastWrite().url, '/api/auth/mfa/disable');
    assert.deepEqual(f.body(f.lastWrite()), { totp_code: '654321' });

    f.answerPrompt(' 111111 ');
    f.el('mfa-regen-codes-btn').click();
    await settle();
    assert.equal(f.lastWrite().url, '/api/auth/mfa/regenerate-backup-codes');
    assert.deepEqual(f.body(f.lastWrite()), { totp_code: '111111' });
    assert.deepEqual(f.el('mfa-regen-codes-display').children.map(child => child.textContent), ['<i>N1</i>']);
    assert.equal(f.el('mfa-backup-count').textContent, '1');
    count = writes();
    f.answerPrompt(null);
    f.el('mfa-regen-codes-btn').click();
    assert.equal(writes(), count, 'a cancelled TOTP prompt sends nothing');
});

test('Capture IQ on a node row lists active nodes as text and queues an exact, validated capture', async () => {
    const nodes = [{ node_id: 'edge 1', host: MARKUP, status: 'active' }, { node_id: 'edge-2', host: 'h', status: 'offline' }];
    const f = dashboard({ routes: (url, options) => url.startsWith('/api/nodes/?') ? nodes
        : options.method === 'POST' ? {} : undefined });
    await settle();
    const capture = id => f.el('nodes-tbody').querySelector(`[data-capture-node="${id}"]`);
    assert.equal(f.el('iq-capture-overlay').style.display, 'none');
    capture('edge 1').click();
    await settle();
    const select = f.el('iq-capture-node-id');
    assert.deepEqual(select.options.map(option => [option.value, option.textContent]), [['edge 1', 'edge 1 (' + MARKUP + ')']]);
    assert.equal(select.value, 'edge 1');
    assert.deepEqual(injected(select), []);
    assert.equal(f.el('iq-capture-overlay').style.display, '');
    assert.equal(f.document.activeElement, f.el('iq-capture-freq'), 'the operator lands in the frequency field');
    f.el('iq-capture-freq').value = '915.5';
    f.el('iq-capture-submit').click();
    await settle();
    const call = f.lastWrite();
    assert.equal(call.url, '/api/nodes/edge%201/capture');
    assert.equal(call.headers['X-CSRF-Token'], CSRF);
    // The page's own defaults: 1000 ms at 2.4 MS/s, the node's scan gain, and no class tag.
    assert.deepEqual(f.body(call), { freq_hz: 915500000, duration_ms: 1000, sample_rate: 2400000 });
    assert.ok(f.toasts().includes('IQ capture queued for edge 1 at 915.5 MHz'));
    // A bad frequency sends nothing.
    capture('edge 1').click();
    await settle();
    const count = f.writes().length;
    f.el('iq-capture-freq').value = '-5';
    f.el('iq-capture-submit').click();
    assert.equal(f.writes().length, count);
    assert.equal(f.el('iq-capture-status').textContent, 'Invalid frequency');
    // An offline node cannot be targeted: it is not offered, so nothing is selected or sent.
    capture('edge-2').click();
    await settle();
    assert.equal(select.value, '');
    f.el('iq-capture-freq').value = '433.92';
    f.el('iq-capture-submit').click();
    assert.equal(f.writes().length, count);
    assert.equal(f.el('iq-capture-status').textContent, 'Select a target node');
});

// Defense in depth: node IDs are pattern-validated at registration today.
test('the IQ capture fallback node option is built from text, not markup', async () => {
    // The node table is already shown; the dialog's own node lookup then fails.
    let listed = 0;
    const f = dashboard({ routes: url => url.startsWith('/api/nodes/?')
        ? (listed++ ? response(503, {}) : [{ node_id: 'edge-<img src=x onerror=alert(1)>', host: 'h', status: 'active' }]) : undefined });
    await settle();
    f.el('nodes-tbody').querySelector('[data-capture-node]').click();
    await settle();
    assert.deepEqual(injected(f.el('iq-capture-node-id')), []);
});

test('loading-state retry names are looked up, never evaluated as code', async () => {
    const f = dashboard();
    await settle();
    f.context.setLoadingState('retry-box', true);
    assert.equal(f.el('retry-box').textContent, 'Loading...');
    f.context.setLoadingState('retry-box', false, 'Failed to load', 'window.pwned=1');
    f.el('retry-box').querySelector('.retry-btn').click();
    assert.equal(f.context.pwned, undefined);
    let retried = 0;
    f.context.setLoadingState('retry-box', false, 'Failed to load', () => retried++);
    f.el('retry-box').querySelector('.retry-btn').click();
    assert.equal(retried, 1);
});
