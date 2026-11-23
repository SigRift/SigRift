/* The shipped dashboard.js controls an operator drives directly: the alert
 * rule builder, tab navigation and keyboard shortcuts, card and display
 * preferences, dialogs (focus trap, Escape), MFA settings, IQ capture and
 * cross-panel drill-down. Booted in the parsed DOM of untrusted_dom.cjs with
 * the real fetch and timer paths. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { bootDashboard, response, settle } = require('./untrusted_dom.cjs');

const INDEX = fs.readFileSync(path.resolve(__dirname, '../../../src/sigrift/bridge/templates/index.html'), 'utf8');
const NAV = /<nav class="tab-bar" id="dashboard-tabs"[^>]*>([\s\S]*?)<\/nav>/.exec(INDEX)[1];
const CSRF = 'csrf-abc123';

const event = (f, type, init) => new f.context.Event(type, init);
const change = (f, el, value) => { el.value = value; el.dispatchEvent(event(f, 'change')); };
const type = (f, el, value) => { el.value = value; el.dispatchEvent(event(f, 'input')); };
const key = (f, name, init = {}) => {
    const e = event(f, 'keydown', { key: name, target: f.document.activeElement || f.document.body, ...init });
    f.document.dispatchEvent(e);
    return e;
};

/* The page's own tab bar, wired the way the constructor wires it. */
const TAB_PANELS = ['nav:dashboard-tabs', 'tab-summary', 'tab-alerts', 'tab-map', 'tab-rf', 'tab-deployment'];
function tabBar(f) {
    f.el('dashboard-tabs').innerHTML = NAV;
    f.db._initTabs();
    return name => f.el('dashboard-tabs').querySelector(`[data-tab="${name}"]`);
}
const activeTab = f => f.el('dashboard-tabs').querySelector('.tab-btn.active').getAttribute('data-tab');
/* DOM nodes are compared by identity and named briefly on failure: assert's own
 * diff would print, and deepEqual would walk, the whole linked document. */
const describeNode = node => (node && node.nodeType === 1
    ? `<${node.localName}${node.id ? '#' + node.id : ''}${node.getAttribute('data-capture-node') ? '[data-capture-node]' : ''}>` : String(node));
function sameNode(actual, expected, message = 'focus') {
    if (actual !== expected) assert.fail(`${message}: ${describeNode(actual)} is not ${describeNode(expected)}`);
}
const leases = protocols => [{ node_id: 'edge-1', host: 'h', status: 'active', scanner_status: Object.fromEntries(protocols.map(protocol =>
    [protocol, { protocol, state: 'running', active: true, expires_in_seconds: 120, reported_at: new Date().toISOString() }])) }];

/* -- Condition rule builder -------------------------------------------- */

const BUILDER = ['cb-title', 'input:cb-rule-name', 'select:cb-rule-severity', 'select:cb-rule-logic', 'input:cb-cooldown',
    'input:cb-enabled', 'input:cb-editing-rule-id', 'cb-conditions', 'p:cb-no-conditions', 'cb-rule-preview',
    'button:cb-add-condition', 'button:cb-save-rule', 'button:cb-test-rule', 'button:cb-cancel', 'span:cb-test-result',
    'condition-builder', 'condition-rules-list', 'p:condition-rules-empty'];

test('the rule builder shows field hints, a band picker and operator-specific inputs, with a live plain-language preview', async () => {
    const f = bootDashboard({ ids: BUILDER });
    await settle();
    const rows = () => f.el('cb-conditions').querySelectorAll('.cb-condition-row');
    const add = () => { f.el('cb-add-condition').click(); return rows().at(-1); };
    const preview = () => f.el('cb-rule-preview').textContent;
    const parts = row => ({ field: row.querySelector('.cb-field-select'), op: row.querySelector('.cb-op-select'),
        value: row.querySelector('.cb-value-input'), max: row.querySelector('.cb-value2-input'), hint: row.querySelector('.cb-field-hint'),
        picker: row.querySelector('.cb-band-picker'), badge: row.querySelector('.cb-logic-badge') });

    const first = parts(add());
    assert.equal(f.el('cb-no-conditions').style.display, 'none');
    assert.equal(first.badge === null, true, 'the first condition has no AND/OR badge');
    assert.equal(first.hint.textContent, 'Typical: 88M-6G. Use band picker below.');
    assert.equal(first.picker.style.display, 'flex');
    const bands = first.picker.querySelectorAll('.cb-band-btn');
    assert.deepEqual(bands.map(button => button.textContent),
        ['FM Broadcast', 'VHF Air', 'ISM 433', 'ISM 868', 'ISM 915', 'GSM 900', 'WiFi 2.4G', 'WiFi 5G']);
    assert.equal(preview(), 'Alert when Frequency (Hz) equals ?');
    bands[2].click();
    assert.deepEqual([first.op.value, first.value.value, first.max.value, first.max.style.display], ['between', '433050000', '434790000', '']);
    assert.equal(preview(), 'Alert when Frequency (Hz) between 433.1 MHz and 434.8 MHz');

    // Each operator asks for the input it needs.
    const inputs = () => [first.value.placeholder, first.max.style.display];
    change(f, first.op, 'in');
    assert.deepEqual(inputs(), ['val1, val2, ...', 'none']);
    change(f, first.op, 'gt');
    assert.deepEqual(inputs(), ['value', 'none']);
    change(f, first.op, 'between');
    assert.deepEqual(inputs(), ['min', '']);

    const second = parts(add());
    assert.equal(second.badge.textContent, 'AND');
    change(f, second.field, 'power_dbm');
    assert.deepEqual([second.hint.textContent, second.picker.style.display], ['Typical range: -80 to -10', 'none']);
    change(f, second.op, 'gt');
    type(f, second.value, '-40');
    assert.equal(preview(), 'Alert when Frequency (Hz) between 433.1 MHz and 434.8 MHz AND Power (dBm) greater than -40');
    change(f, f.el('cb-rule-logic'), 'OR');
    assert.equal(second.badge.textContent, 'OR', 'changing the rule logic relabels every badge');
    const third = parts(add());
    assert.equal(third.badge.textContent, 'OR');
    change(f, third.field, 'node_id');
    type(f, third.value, 'edge-1');
    assert.equal(preview(), 'Alert when Frequency (Hz) between 433.1 MHz and 434.8 MHz OR Power (dBm) greater than -40 OR Node ID equals edge-1');

    // Removing the first condition makes the next one first, without a badge.
    rows()[0].querySelector('.cb-remove-btn').click();
    assert.equal(rows().length, 2);
    assert.equal(rows()[0].querySelectorAll('.cb-logic-badge').length, 0);
    assert.equal(rows()[1].querySelector('.cb-logic-badge').textContent, 'OR');
    for (const row of rows()) row.querySelector('.cb-remove-btn').click();
    assert.equal(f.el('cb-no-conditions').style.display, '', 'the empty hint returns with the last condition');
});

test('saving a new rule posts typed condition values, then resets the form; a failed save says so', async () => {
    let status = 200;
    const f = bootDashboard({ ids: BUILDER, routes: (url, options) => options.method === 'POST' ? response(status, {}) : undefined });
    await settle();
    const add = (field, op, value, max) => {
        f.el('cb-add-condition').click();
        const row = f.el('cb-conditions').querySelectorAll('.cb-condition-row').at(-1);
        change(f, row.querySelector('.cb-field-select'), field);
        change(f, row.querySelector('.cb-op-select'), op);
        type(f, row.querySelector('.cb-value-input'), value);
        if (max !== undefined) type(f, row.querySelector('.cb-value2-input'), max);
    };
    f.el('cb-rule-name').value = '  Rogue 433  ';
    change(f, f.el('cb-rule-severity'), 'critical');
    change(f, f.el('cb-rule-logic'), 'OR');
    f.el('cb-cooldown').value = 'soon';
    add('power_dbm', 'gt', ' -40 ');
    add('snr_db', 'lte', 'loud');
    add('node_id', 'eq', 'edge-1');
    add('confidence', 'in', '0.5, high, ');
    add('family', 'not_in', 'fsk, ask');
    add('signal_class', 'between', 'a', 'b');
    add('bandwidth_hz', 'between', '', '2e6');
    const before = f.requests.length;
    f.el('cb-save-rule').click();
    await settle();
    const call = f.lastWrite();
    assert.deepEqual([call.method, call.url, call.headers['X-CSRF-Token']], ['POST', '/api/alerts/rules/conditions', CSRF]);
    assert.deepEqual(f.body(call), { name: 'Rogue 433', severity: 'critical', logic: 'OR', cooldown_seconds: 300, enabled: true,
        notify_webhook: true, conditions: [
            { field: 'power_dbm', operator: 'gt', value: -40 },
            { field: 'snr_db', operator: 'lte', value: 0 },
            { field: 'node_id', operator: 'eq', value: 'edge-1' },
            { field: 'confidence', operator: 'in', value: [0.5, 0] },
            { field: 'family', operator: 'not_in', value: ['fsk', 'ask'] },
            { field: 'signal_class', operator: 'between', value: ['a', 'b'] },
            { field: 'bandwidth_hz', operator: 'between', value: [0, 2000000] }] });
    assert.ok(f.toasts().includes('Rule created'));
    assert.deepEqual([f.el('cb-title').textContent, f.el('cb-rule-name').value, f.el('cb-rule-logic').value,
        f.el('cb-conditions').children.length, f.el('cb-no-conditions').style.display], ['New Alert Rule', '', 'AND', 0, '']);
    assert.ok(f.requests.slice(before).some(c => c.method === 'GET' && c.url.startsWith('/api/alerts/rules/conditions?')), 'the rule list reloads');

    status = 500;
    f.el('cb-rule-name').value = 'Again';
    add('freq_hz', 'gt', '1');
    f.el('cb-save-rule').click();
    await settle();
    assert.ok(f.toasts().includes('Failed to create rule'));
    assert.equal(f.el('cb-rule-name').value, 'Again', 'a failed save keeps the operator\'s input');
});

test('Test Rule needs a saved rule, then dry-runs exactly that rule and reports matches or failure', async () => {
    const rules = [{ rule_id: 'r 1', name: 'Loud', severity: 'critical', logic: 'AND', cooldown_seconds: 60,
        conditions: [{ field: 'power_dbm', operator: 'gt', value: -40 }] }, { rule_id: 'r 2', name: 'Bare' }];
    let result = { detections_scanned: 120, matches: 3 };
    const f = bootDashboard({ ids: BUILDER, routes: (url, options) => {
        if (url.startsWith('/api/alerts/rules/conditions?')) return rules;
        if (url.endsWith('/test')) return result;
        return undefined;
    } });
    await settle();
    const resultText = () => [f.el('cb-test-result').textContent, f.el('cb-test-result').style.color];
    f.el('cb-test-rule').click();
    assert.deepEqual(f.writes(), [], 'an unsaved rule is never sent');
    assert.ok(f.toasts().includes('Save the rule first, then test it'));

    const list = f.el('condition-rules-list');
    list.querySelector('[data-cr-edit="r 1"]').click();
    assert.equal(f.el('cb-conditions').querySelector('.cb-value-input').value, '-40');
    f.el('cb-test-rule').click();
    assert.equal(f.el('cb-test-result').textContent, 'Testing...');
    await settle();
    assert.deepEqual([f.lastWrite().url, f.body(f.lastWrite()), f.lastWrite().headers['X-CSRF-Token']],
        ['/api/alerts/rules/conditions/r%201/test', { minutes: 60, limit: 1000 }, CSRF]);
    assert.deepEqual(resultText(), ['Scanned 120 detections, 3 matches', 'var(--accent-green)']);
    result = { detections_scanned: 50, matches: 0 };
    f.el('cb-test-rule').click();
    await settle();
    assert.deepEqual(resultText(), ['Scanned 50 detections, 0 matches', 'var(--text-secondary)']);
    result = response(500, {});
    f.el('cb-test-rule').click();
    await settle();
    assert.deepEqual(resultText(), ['Test failed', 'var(--accent-red)']);

    // A stored rule with no optional fields opens with the form defaults.
    list.querySelector('[data-cr-edit="r 2"]').click();
    assert.deepEqual([f.el('cb-rule-severity').value, f.el('cb-rule-logic').value, f.el('cb-cooldown').value, f.el('cb-editing-rule-id').value,
        f.el('cb-conditions').children.length, f.el('cb-no-conditions').style.display], ['warning', 'AND', '300', 'r 2', 0, '']);
    assert.equal(f.el('condition-builder').scrolledIntoView, true);
    f.el('cb-cancel').click();
    assert.deepEqual([f.el('cb-title').textContent, f.el('cb-editing-rule-id').value, f.el('cb-test-result').textContent], ['New Alert Rule', '', '']);
});

test('the signal-class value field suggests classes observed in the last 24 h', async () => {
    const f = bootDashboard({ ids: BUILDER, routes: url => url.startsWith('/api/status?freq_hours=24')
        ? { active_frequency_list: [{ freq_mhz: 433.9, count: 4, classes: 'lora,ook', nodes: 'a' }] } : undefined });
    await settle();
    f.el('cb-add-condition').click();
    const row = f.el('cb-conditions').querySelector('.cb-condition-row');
    change(f, row.querySelector('.cb-field-select'), 'signal_class');
    await settle();
    type(f, row.querySelector('.cb-value-input'), 'lo');
    assert.deepEqual(row.querySelectorAll('.cb-autocomplete-item').map(item => item.textContent), ['lora']);
});

test('signal-class suggestions split every row\'s class list, once per class', async () => {
    const f = bootDashboard({ ids: BUILDER, routes: url => url.startsWith('/api/status?freq_hours=24')
        ? { active_frequency_list: [{ freq_mhz: 433.9, count: 4, classes: 'lora, ook', nodes: 'a' },
            { freq_mhz: 868.3, count: 2, classes: 'lora,lorawan,', nodes: 'a' }, { freq_mhz: 915, count: 1, classes: null, nodes: 'a' },
            { freq_mhz: 100.1, count: 1, signal_class: 'fm', nodes: 'a' }] } : undefined });
    await settle();
    f.el('cb-add-condition').click();
    const row = f.el('cb-conditions').querySelector('.cb-condition-row');
    change(f, row.querySelector('.cb-field-select'), 'signal_class');
    await settle();
    const suggest = value => { type(f, row.querySelector('.cb-value-input'), value); return row.querySelectorAll('.cb-autocomplete-item').map(item => item.textContent); };
    assert.deepEqual(suggest('lo'), ['lora', 'lorawan']);
    assert.deepEqual(suggest('OOK'), ['ook'], 'surrounding spaces are trimmed and matching ignores case');
    assert.deepEqual(suggest('fm'), ['fm'], 'a row with a single signal_class is read too');
    row.querySelectorAll('.cb-autocomplete-item')[0].click();
    assert.equal(row.querySelector('.cb-value-input').value, 'fm');
});

test('signal-class suggestions take a row\'s class list over its single signal_class', async () => {
    const f = bootDashboard({ ids: BUILDER, routes: url => url.startsWith('/api/status?freq_hours=24')
        ? { active_frequency_list: [{ freq_mhz: 433.9, count: 4, classes: 'lora,ook', signal_class: 'fsk', nodes: 'a' }] } : undefined });
    await settle();
    f.el('cb-add-condition').click();
    const row = f.el('cb-conditions').querySelector('.cb-condition-row');
    change(f, row.querySelector('.cb-field-select'), 'signal_class');
    await settle();
    const suggest = value => { type(f, row.querySelector('.cb-value-input'), value); return row.querySelectorAll('.cb-autocomplete-item').map(item => item.textContent); };
    assert.deepEqual(suggest('o'), ['lora', 'ook'], 'the comma-joined classes field wins');
    assert.deepEqual(suggest('fsk'), [], 'the signal_class beside it is not read');
});

/* -- Tabs, shortcuts and display preferences ---------------------------- */

test('tab buttons switch panels, remember the tab and bring each tab back to where the operator left it', async () => {
    const f = bootDashboard({ ids: TAB_PANELS });
    await settle();
    const tab = tabBar(f), root = f.document.documentElement;
    assert.equal(activeTab(f), 'summary');
    assert.equal(tab('rf').disabled, true, 'a scanner tab without a live scanner cannot be opened');
    root.scrollTop = 800;
    tab('alerts').click();
    assert.equal(activeTab(f), 'alerts');
    assert.deepEqual([f.el('tab-alerts').classList.contains('active'), f.el('tab-summary').classList.contains('active'),
        tab('alerts').getAttribute('aria-selected'), tab('summary').getAttribute('aria-selected')], [true, false, 'true', 'false']);
    assert.equal(f.context.localStorage.getItem('bridge_active_tab'), 'alerts');
    assert.equal(f.context.localStorage.getItem('bridge_tab_scroll_summary'), '800');

    // A panel that scrolls itself is its own scroll container.
    const alerts = f.el('tab-alerts');
    Object.assign(alerts, { scrollHeight: 3000, clientHeight: 500, scrollTop: 1200 });
    Object.assign(root, { scrollTop: 0, scrollHeight: 2000, clientHeight: 600 });
    tab('summary').click();
    assert.equal(f.context.localStorage.getItem('bridge_tab_scroll_alerts'), '1200');
    assert.equal(root.scrollTop, 0, 'restored after the next frame, once laid out');
    await f.tick(16);
    assert.equal(root.scrollTop, 800);
    alerts.scrollTop = 0;
    tab('alerts').click();
    await f.tick(16);
    assert.equal(alerts.scrollTop, 1200);

    // A saved offset deeper than the tab can now scroll is clamped; no scroll room leaves it alone.
    Object.assign(root, { scrollTop: 0, scrollHeight: 900, clientHeight: 600 });
    tab('summary').click();
    await f.tick(16);
    assert.equal(root.scrollTop, 300);
    Object.assign(alerts, { scrollHeight: 400, clientHeight: 500, scrollTop: 0 });
    Object.assign(root, { scrollTop: 0, scrollHeight: 600, clientHeight: 600 });
    tab('alerts').click();
    await f.tick(16);
    assert.deepEqual([alerts.scrollTop, root.scrollTop], [0, 0]);
});

test('opening the Map tab starts the map views and leaving it pauses them; blocked storage never breaks navigation', async () => {
    const f = bootDashboard({ ids: TAB_PANELS });
    await settle();
    const tab = tabBar(f), calls = [];
    f.db.geoMap = { init: () => calls.push('geo init'), invalidateSize: () => calls.push('geo resize') };
    f.db.tdoaView = { start: () => calls.push('tdoa start'), stop: () => calls.push('tdoa stop') };
    f.context.activateMapPanel = () => calls.push('map panel on');
    f.context.deactivateMapPanel = () => calls.push('map panel off');
    tab('map').click();
    assert.deepEqual([...calls].sort(), ['geo init', 'geo resize', 'map panel on', 'tdoa stop']);
    assert.ok(calls.indexOf('geo init') < calls.indexOf('geo resize'), 'the map is sized after it is created');
    calls.length = 0;
    tab('deployment').click();
    assert.deepEqual([...calls].sort(), ['map panel off', 'tdoa stop']);

    const storage = f.context.localStorage;
    storage.getItem = () => { throw new Error('SecurityError'); };
    storage.setItem = () => { throw new Error('QuotaExceededError'); };
    assert.doesNotThrow(() => tab('alerts').click());
    assert.equal(activeTab(f), 'alerts');
    tab('summary').click();
    assert.equal(activeTab(f), 'summary');
});

test('keyboard shortcuts: ? toggles the overlay, Escape or a background click closes it, number keys switch tabs', async () => {
    const f = bootDashboard({ ids: [...TAB_PANELS, 'shortcut-overlay', 'input:node-search'] });
    await settle();
    tabBar(f);
    const overlay = f.el('shortcut-overlay'), visible = () => overlay.classList.contains('visible');
    assert.deepEqual(f.toasts(), []);
    await f.tick(3000);
    assert.ok(f.toasts().includes('Press ? for keyboard shortcuts'), 'first visit hints at the overlay');
    assert.equal(f.context.localStorage.getItem('bridge_shortcuts_seen'), 'true');

    assert.equal(key(f, '?').defaultPrevented, true);
    assert.equal(visible(), true);
    key(f, '?');
    assert.equal(visible(), false);
    key(f, '?');
    assert.equal(key(f, 'Escape').defaultPrevented, true);
    assert.equal(visible(), false);
    assert.equal(key(f, 'Escape').defaultPrevented, false, 'Escape with nothing open is left alone');

    key(f, '8');
    assert.equal(activeTab(f), 'alerts');
    key(f, '4', { ctrlKey: true });
    key(f, '4', { altKey: true });
    assert.equal(activeTab(f), 'alerts', 'modified number keys belong to the browser');
    key(f, '4');
    assert.equal(activeTab(f), 'map');
    key(f, '2');
    assert.equal(activeTab(f), 'summary', 'a scanner tab without a live scanner falls back to Summary');
    key(f, '?', { metaKey: true });
    assert.equal(visible(), false);

    // Typing in a field is never a shortcut.
    f.el('node-search').focus();
    key(f, '?');
    key(f, '8');
    assert.deepEqual([visible(), activeTab(f)], [false, 'summary']);
    f.el('node-search').blur();

    key(f, '?');
    const panel = f.document.createElement('div');
    overlay.appendChild(panel);
    panel.click();
    assert.equal(visible(), true, 'a click inside the panel keeps it open');
    overlay.click();
    assert.equal(visible(), false);
});

test('card headers collapse and expand their card and the choice persists', async () => {
    const f = bootDashboard();
    await settle();
    const card = name => {
        const section = f.document.createElement('section');
        section.className = 'card';
        section.innerHTML = `<div class="card-header" data-collapse="${name}"><h2>${name}</h2></div><div class="card-content"></div>`;
        f.document.body.appendChild(section);
        return section;
    };
    const nodes = card('nodes');
    const orphan = f.document.createElement('div');
    orphan.setAttribute('data-collapse', 'orphan');
    f.document.body.appendChild(orphan);
    f.db._initCards();
    const header = nodes.querySelector('.card-header');
    header.click();
    assert.equal(nodes.classList.contains('collapsed'), true);
    assert.deepEqual(JSON.parse(f.context.localStorage.getItem('bridge_collapsed')), { nodes: true });
    header.click();
    assert.equal(nodes.classList.contains('collapsed'), false);
    assert.deepEqual(JSON.parse(f.context.localStorage.getItem('bridge_collapsed')), { nodes: false });
    assert.doesNotThrow(() => orphan.click(), 'a header outside any card is ignored');

    // The next page load starts with the saved state; unreadable or unwritable storage is harmless.
    f.context.localStorage.setItem('bridge_collapsed', JSON.stringify({ alerts: true }));
    f.db._loadCollapsed();
    const alerts = card('alerts');
    f.db._initCards();
    assert.equal(alerts.classList.contains('collapsed'), true);
    f.context.localStorage.setItem('bridge_collapsed', '{not json');
    f.db._loadCollapsed();
    assert.deepEqual({ ...f.db.collapsed }, {});
    f.context.localStorage.setItem = () => { throw new Error('QuotaExceededError'); };
    alerts.querySelector('.card-header').click();
    assert.equal(alerts.classList.contains('collapsed'), false);
});

test('the theme picker applies and remembers a theme and warns on themes that mute urgency colours', async () => {
    const f = bootDashboard({ ids: ['select:theme-select', 'span:theme-warning'] });
    await settle();
    const select = f.el('theme-select'), warning = f.el('theme-warning'), root = f.document.documentElement;
    assert.deepEqual([select.value, root.getAttribute('data-theme'), warning.style.display], ['dark', 'dark', 'none']);
    change(f, select, 'matrix');
    assert.deepEqual([root.getAttribute('data-theme'), f.context.localStorage.getItem('bridge_theme'), warning.style.display], ['matrix', 'matrix', '']);
    change(f, select, 'light');
    assert.deepEqual([root.getAttribute('data-theme'), warning.style.display], ['light', 'none']);
});

test('Show all columns toggles the detailed node table and is remembered', async () => {
    const f = bootDashboard({ ids: ['input:nodes-show-details', 'table:nodes-table'] });
    await settle();
    const box = f.el('nodes-show-details'), table = f.el('nodes-table');
    assert.deepEqual([box.checked, table.classList.contains('nodes-detail-mode')], [false, false]);
    box.checked = true;
    box.dispatchEvent(event(f, 'change'));
    assert.deepEqual([table.classList.contains('nodes-detail-mode'), f.context.localStorage.getItem('bridge_nodes_detail')], [true, 'true']);
    box.checked = false;
    box.dispatchEvent(event(f, 'change'));
    assert.deepEqual([table.classList.contains('nodes-detail-mode'), f.context.localStorage.getItem('bridge_nodes_detail')], [false, 'false']);
    // The saved choice applies when the page loads.
    f.context.localStorage.setItem('bridge_nodes_detail', 'true');
    f.db._initNodeDetails();
    assert.deepEqual([box.checked, table.classList.contains('nodes-detail-mode')], [true, true]);
});

/* -- Dialogs ------------------------------------------------------------- */

const MFA = ['button:settings-btn', 'mfa-settings-overlay', 'button:mfa-settings-close', 'mfa-loading', 'mfa-content', 'mfa-status-badge',
    'mfa-enable-section', 'mfa-enabled-section', 'mfa-setup-section', 'mfa-backup-count', 'button:mfa-enable-btn', 'button:mfa-disable-btn',
    'button:mfa-verify-setup-btn', 'button:mfa-regen-codes-btn', 'input:mfa-verify-code', 'input:mfa-disable-code', 'mfa-setup-error',
    'mfa-disable-error', 'mfa-provisioning-uri', 'mfa-secret-display', 'mfa-backup-codes-display', 'mfa-regen-codes-display'];

test('MFA settings: enabling via Enter, an enabled status, and every failed step leaves a retryable message', async () => {
    let mfaOn = false, me = 200, setup = 500, regen = 500;
    const f = bootDashboard({ ids: MFA, routes: (url, options) => {
        if (url.startsWith('/api/auth/me')) return response(me, { username: 'op', display_name: 'Operator', role: 'admin', mfa_enabled: mfaOn });
        if (url === '/api/auth/mfa/setup') return response(setup, { provisioning_uri: 'otpauth://totp/x', secret: 'S', backup_codes: ['B1'] });
        if (url === '/api/auth/mfa/verify-setup') { mfaOn = true; return {}; }
        if (url === '/api/auth/mfa/disable') return response(400, {});
        if (url === '/api/auth/mfa/regenerate-backup-codes') return response(regen, {});
        return options.method === 'POST' ? {} : undefined;
    } });
    await settle();
    const overlay = f.el('mfa-settings-overlay'), shown = id => f.el(id).style.display;
    f.document.body.style.overflow = '';
    f.el('settings-btn').focus();
    f.el('settings-btn').click();
    await settle();
    assert.deepEqual([shown('mfa-settings-overlay'), f.document.body.style.overflow], ['', 'hidden']);
    assert.deepEqual([f.el('mfa-status-badge').textContent, f.el('mfa-backup-count').textContent], ['Disabled', '--']);

    f.el('mfa-enable-btn').click();
    await settle();
    assert.deepEqual(f.dialogs.at(-1), ['alert', 'Failed to start MFA setup.']);
    assert.equal(f.el('mfa-enable-btn').disabled, false);
    setup = 200;
    f.el('mfa-enable-btn').click();
    await settle();
    assert.equal(shown('mfa-setup-section'), '');
    const verify = f.el('mfa-verify-code');
    verify.value = '123456';
    verify.dispatchEvent(event(f, 'keydown', { key: 'a' }));
    assert.equal(f.lastWrite().url, '/api/auth/mfa/setup', 'only Enter submits');
    verify.dispatchEvent(event(f, 'keydown', { key: 'Enter' }));
    await settle();
    assert.deepEqual([f.lastWrite().url, f.body(f.lastWrite())], ['/api/auth/mfa/verify-setup', { totp_code: '123456' }]);
    assert.equal(f.el('mfa-verify-setup-btn').disabled, false);
    assert.deepEqual([f.el('mfa-status-badge').textContent, shown('mfa-enabled-section'), shown('mfa-enable-section'), shown('mfa-setup-section')],
        ['Enabled', '', 'none', 'none'], 'the status reloads as enabled');

    const disable = f.el('mfa-disable-code');
    disable.value = '654321';
    f.answerConfirm(true);
    disable.dispatchEvent(event(f, 'keydown', { key: 'Enter' }));
    await settle();
    assert.equal(f.lastWrite().url, '/api/auth/mfa/disable');
    assert.deepEqual([f.el('mfa-disable-error').textContent, shown('mfa-disable-error'), f.el('mfa-disable-btn').disabled],
        ['Failed to disable MFA.', '', false]);

    const writes = f.writes().length;
    f.answerConfirm(false);
    f.el('mfa-regen-codes-btn').click();
    assert.equal(f.writes().length, writes, 'regenerating codes needs confirmation');
    f.answerConfirm(true);
    f.answerPrompt('222222');
    f.el('mfa-regen-codes-btn').click();
    await settle();
    assert.deepEqual([f.lastWrite().url, f.el('mfa-disable-error').textContent, f.el('mfa-regen-codes-btn').disabled],
        ['/api/auth/mfa/regenerate-backup-codes', 'Failed to regenerate backup codes.', false]);

    f.el('mfa-regen-codes-display').style.display = '';
    f.el('mfa-settings-close').click();
    assert.deepEqual([shown('mfa-settings-overlay'), overlay.getAttribute('aria-hidden'), shown('mfa-setup-section'), shown('mfa-regen-codes-display'),
        f.document.body.style.overflow], ['none', 'true', 'none', 'none', '']);
    sameNode(f.document.activeElement, f.el('settings-btn'), 'focus returns to the settings button');

    // A failed status load says so; a click on the backdrop closes the dialog.
    me = 503;
    f.el('settings-btn').click();
    await settle();
    assert.equal(f.el('mfa-loading').textContent, 'Failed to load user info.');
    overlay.dispatchEvent(event(f, 'click'));
    assert.equal(shown('mfa-settings-overlay'), 'none');
});

const IQ = ['tbody:nodes-tbody', 'iq-capture-overlay', 'button:iq-capture-close', 'select:iq-capture-node-id', 'input:iq-capture-freq',
    'input:iq-capture-duration', 'input:iq-capture-samplerate', 'input:iq-capture-gain', 'iq-capture-status', 'button:iq-capture-submit',
    'button:iq-capture-cancel'];

test('the IQ capture dialog traps Tab focus, closes on Escape and returns focus to the button that opened it', async () => {
    const nodes = [{ node_id: 'edge-1', host: 'h', status: 'active' }];
    const f = bootDashboard({ ids: IQ, routes: url => url.startsWith('/api/nodes/?') ? nodes : undefined });
    await settle();
    const overlay = f.el('iq-capture-overlay');
    const [close, freq, submit, cancel] = ['iq-capture-close', 'iq-capture-freq', 'iq-capture-submit', 'iq-capture-cancel'].map(id => f.el(id));
    for (const el of [close, freq, submit, cancel]) overlay.appendChild(el);   // the dialog's own controls, as on the page
    const opener = f.el('nodes-tbody').querySelector('[data-capture-node="edge-1"]');
    opener.focus();
    opener.click();
    await settle();
    sameNode(f.document.activeElement, freq, 'the first field has focus');
    const tab = (shiftKey = false) => key(f, 'Tab', { shiftKey });
    f.document.activeElement = cancel;
    assert.equal(tab().defaultPrevented, true);
    sameNode(f.document.activeElement, close, 'Tab on the last control wraps to the first');
    assert.equal(tab(true).defaultPrevented, true);
    sameNode(f.document.activeElement, cancel, 'Shift+Tab on the first wraps to the last');
    f.document.activeElement = submit;
    assert.equal(tab().defaultPrevented, false, 'Tab between inner controls is left to the browser');
    f.document.activeElement = f.document.body;
    tab();
    sameNode(f.document.activeElement, close, 'focus outside the dialog is pulled back in');
    f.document.activeElement = f.document.body;
    tab(true);
    sameNode(f.document.activeElement, cancel, 'Shift+Tab from outside lands on the last control');
    assert.equal(key(f, 'Enter').defaultPrevented, false);

    assert.equal(key(f, 'Escape').defaultPrevented, true);
    assert.equal(overlay.style.display, 'none');
    sameNode(f.document.activeElement, opener, 'focus returns to the button that opened the dialog');
    f.document.activeElement = cancel;
    tab();
    sameNode(f.document.activeElement, cancel, 'the trap is removed with the dialog');

    // Every way out closes it: the close and cancel buttons and the backdrop.
    for (const exit of [() => close.click(), () => cancel.click(), () => overlay.dispatchEvent(event(f, 'click'))]) {
        opener.click();
        await settle();
        assert.equal(overlay.style.display, '');
        freq.click();                    // a click inside the dialog is not a backdrop click
        assert.equal(overlay.style.display, '');
        exit();
        assert.equal(overlay.style.display, 'none');
    }
    // A dialog shown directly (not through the focus trap) still closes.
    overlay.style.display = '';
    cancel.click();
    assert.equal(overlay.style.display, 'none');

    // Opened from a detection, with the frequency filled in, focus starts on the dialog's first control.
    f.db._openIQCaptureDialog('edge-1', 433.92);
    await settle();
    assert.equal(freq.value, '433.92');
    sameNode(f.document.activeElement, close, 'a capture with a preset frequency starts at the first control');
});

test('an IQ capture started from a detection carries its class and the operator\'s settings; a refused capture keeps the dialog open', async () => {
    let status = 200;
    const nodes = [{ node_id: 'edge-1', host: 'h', status: 'active' }, { node_id: 'edge-2', host: 'h2', status: 'active' }];
    const f = bootDashboard({ ids: IQ, routes: (url, options) => url.startsWith('/api/nodes/?') ? nodes
        : options.method === 'POST' ? response(status, {}) : undefined });
    await settle();
    const overlay = f.el('iq-capture-overlay');
    f.db._openIQCaptureDialog('edge-2', 433.92, 'lora');
    await settle();
    assert.deepEqual([f.el('iq-capture-node-id').value, f.el('iq-capture-freq').value, overlay.getAttribute('data-signal-class')],
        ['edge-2', '433.92', 'lora']);
    f.el('iq-capture-duration').value = '250';
    f.el('iq-capture-samplerate').value = '10';
    f.el('iq-capture-gain').value = '20.5';
    f.el('iq-capture-submit').click();
    await settle();
    assert.deepEqual([f.lastWrite().url, f.body(f.lastWrite())], ['/api/nodes/edge-2/capture',
        { freq_hz: 433920000, duration_ms: 250, sample_rate: 10000000, gain_db: 20.5, signal_class: 'lora' }]);
    assert.equal(overlay.style.display, 'none');

    // A class that is not a plain identifier is not forwarded; a refusal is shown in the dialog.
    status = 500;
    f.db._openIQCaptureDialog('edge-1', 915.5, 'lora <b>x</b>');
    await settle();
    f.el('iq-capture-gain').value = '';
    f.el('iq-capture-submit').click();
    await settle();
    assert.deepEqual(f.body(f.lastWrite()), { freq_hz: 915500000, duration_ms: 250, sample_rate: 10000000 });
    // The reason itself is pinned by the reason-dropping apiFetch BUG test in dashboard_security.test.cjs.
    const statusEl = f.el('iq-capture-status');
    assert.ok(statusEl.textContent.length > 0 && statusEl.textContent !== 'Queuing capture...', statusEl.textContent);
    assert.equal(statusEl.style.color, 'var(--accent-red)');
    assert.ok(f.toasts().includes('IQ capture failed: ' + statusEl.textContent), JSON.stringify(f.toasts()));
    assert.equal(overlay.style.display, '', 'the operator can correct and retry');
});

test('legacy overlays close on Escape or their close button, but not on a click inside them', async () => {
    const f = bootDashboard({ ids: ['deep-dive-overlay', 'node-compare-overlay', 'modal-overlay', 'button:modal-close',
        'modal-wide-overlay', 'button:modal-wide-close'] });
    await settle();
    const deepDive = f.el('deep-dive-overlay');
    deepDive.style.display = '';            // detections.js shows its deep dive directly
    assert.equal(key(f, 'Escape').defaultPrevented, false);
    assert.equal(deepDive.style.display, 'none');
    assert.equal(key(f, 'Escape').defaultPrevented, false, 'nothing else to close');
    for (const [overlayId, closeId] of [['modal-overlay', 'modal-close'], ['modal-wide-overlay', 'modal-wide-close']]) {
        const overlay = f.el(overlayId), inner = f.document.createElement('div');
        overlay.appendChild(inner);
        overlay.style.display = '';
        inner.click();
        assert.equal(overlay.style.display, '', overlayId + ': a click inside stays open');
        overlay.dispatchEvent(event(f, 'click'));
        assert.equal(overlay.style.display, 'none', overlayId + ': a backdrop click closes');
        overlay.style.display = '';
        f.el(closeId).click();
        assert.equal(overlay.style.display, 'none', overlayId + ': the close button closes');
    }
});

/* -- Cross-panel drill-down ------------------------------------------- */

/* A drill-down opens its tab and lights up its target within ARRIVED ms, and
 * the highlight is gone FADED ms later: what an operator notices, not the
 * exact internal settle delays. */
const ARRIVED = 500, FADED = 3000;

test('drill-down to a frequency opens Spectrum and highlights the band row that contains it, else the band panel', async () => {
    let protocols = ['sdr'];
    const f = bootDashboard({ ids: [...TAB_PANELS, 'tab-spectrum-analysis', 'tbody:sa-bands-tbody', 'panel-band-occupancy'],
        routes: url => url.startsWith('/api/nodes/?') ? leases(protocols) : undefined });
    await settle();
    tabBar(f);
    const drill = f.context.drillDown, bands = f.el('sa-bands-tbody'), panel = f.el('panel-band-occupancy');
    bands.innerHTML = '<tr><td>FM</td><td>88.0 - 108.0 MHz</td></tr><tr><td>no range</td></tr>'
        + '<tr><td>ISM</td><td>varies</td></tr><tr><td>ISM 433</td><td>433.05 - 434.79 MHz</td></tr>';
    const rows = bands.querySelectorAll('tr'), lit = el => el.classList.contains('drilldown-highlight');
    drill.toSpectrum(433.92e6);
    await f.tick(ARRIVED);
    assert.equal(activeTab(f), 'spectrum-analysis');
    assert.deepEqual(rows.map(lit), [false, false, false, true]);
    assert.equal(rows[3].scrolledIntoView, true);
    await f.tick(FADED);
    assert.equal(lit(rows[3]), false, 'the highlight fades');
    drill.toSpectrum(5800e6);
    await f.tick(ARRIVED);
    assert.deepEqual([rows.some(lit), lit(panel)], [false, true]);
    await f.tick(FADED);
    drill.toSpectrum(null);
    await f.tick(ARRIVED);
    assert.deepEqual([activeTab(f), rows.some(lit), lit(panel)], ['spectrum-analysis', false, false]);

    // Without a live SDR scanner the drill-down stays on Summary and highlights nothing.
    protocols = [];
    await f.tick(10000);
    assert.equal(activeTab(f), 'summary');
    drill.toSpectrum(433.92e6);
    await f.tick(ARRIVED);
    assert.deepEqual([activeTab(f), rows.some(lit), lit(panel)], ['summary', false, false]);
});

test('drill-down to a signal class filters the RF anomaly queue, else opens the class in the signal browser', async () => {
    const f = bootDashboard({ ids: [...TAB_PANELS, 'select:rf-anomaly-filter-key', 'select:rf-anomaly-filter-val', 'anomaly-queue'],
        routes: url => url.startsWith('/api/nodes/?') ? leases(['sdr']) : undefined });
    await settle();
    tabBar(f);
    const drill = f.context.drillDown, queue = f.el('anomaly-queue');
    const filterKey = f.el('rf-anomaly-filter-key'), filterVal = f.el('rf-anomaly-filter-val'), changes = [];
    filterVal.innerHTML += '<option value="lora">lora</option>';
    filterKey.addEventListener('change', () => changes.push(['key', filterKey.value]));
    filterVal.addEventListener('change', () => changes.push(['value', filterVal.value]));
    queue.innerHTML = '<div class="anomaly-card">first</div><div class="anomaly-card">second</div>';
    const panelCalls = [];
    f.db.detectionDashboard = { activate: () => panelCalls.push('rf on'), deactivate: () => panelCalls.push('rf off') };
    drill.toSignalClass('lora');
    await f.tick(ARRIVED);
    assert.equal(activeTab(f), 'rf');
    assert.ok(panelCalls.includes('rf on'));
    assert.deepEqual(changes, [['key', 'signal_class'], ['value', 'lora']], 'the filter key is chosen before its value');
    assert.deepEqual(queue.querySelectorAll('.anomaly-card').map(card => card.classList.contains('drilldown-highlight')), [true, false]);
    await f.tick(FADED);

    // Without the queue filters, a class the signal browser knows opens there; an unknown class highlights the queue.
    filterKey.remove();
    filterVal.remove();
    const viewed = [];
    f.db.signalBrowser = { classes: [{ class_name: 'lora' }], _showViewer: name => viewed.push(name) };
    drill.toSignalClass('lora');
    await f.tick(ARRIVED);
    assert.deepEqual([viewed, f.db.signalBrowser.selCls, queue.classList.contains('drilldown-highlight')], [['lora'], 'lora', false]);
    f.db.detectionDashboard = null;
    drill.toSignalClass('unknown-class');
    await f.tick(ARRIVED);
    assert.deepEqual([viewed, queue.classList.contains('drilldown-highlight')], [['lora'], true]);
    await f.tick(FADED);
    drill.toSignalClass('');
    await f.tick(ARRIVED);
    assert.equal(queue.classList.contains('drilldown-highlight'), false, 'no class, no highlight');
});

test('drill-down to a Bluetooth address filters the device table and highlights that device', async () => {
    const f = bootDashboard({ ids: [...TAB_PANELS, 'tab-bluetooth', 'input:bt-manufacturer-search', 'tbody:bt-device-tbody'],
        routes: url => url.startsWith('/api/nodes/?') ? leases(['bluetooth']) : undefined });
    await settle();
    tabBar(f);
    const drill = f.context.drillDown, tbody = f.el('bt-device-tbody'), rendered = [];
    f.db.btPanel = { devices: ['d1', 'd2'], activate() {}, deactivate() {}, _renderDeviceTable: devices => rendered.push(devices) };
    tbody.innerHTML = '<tr><td>11:22:33:44:55:66</td></tr><tr><td>AA:BB:CC:00:11:22</td></tr>';
    const lit = () => tbody.querySelectorAll('tr').map(row => row.classList.contains('drilldown-highlight'));
    drill.toBluetooth('aa:BB:cc:00:11:22');
    await f.tick(ARRIVED);
    assert.equal(activeTab(f), 'bluetooth');
    assert.deepEqual([f.el('bt-manufacturer-search').value, f.db.btPanel.manufacturerSearch, rendered], ['aa:BB:cc:00:11:22', 'aa:bb:cc:00:11:22', [['d1', 'd2']]]);
    assert.deepEqual(lit(), [false, true]);
    await f.tick(FADED);
    drill.toBluetooth('FF:FF:FF:FF:FF:FF');
    await f.tick(ARRIVED);
    assert.deepEqual(lit(), [true, false], 'an address not in the table highlights its first row');
    await f.tick(FADED);
    tbody.innerHTML = '';
    drill.toBluetooth('FF:FF:FF:FF:FF:FF');
    await assert.doesNotReject(f.tick(ARRIVED));
    tbody.remove();
    drill.toBluetooth('FF:FF:FF:FF:FF:FF');
    await assert.doesNotReject(f.tick(ARRIVED));
    const searches = rendered.length;
    drill.toBluetooth('');
    await f.tick(ARRIVED);
    assert.equal(rendered.length, searches, 'no address, no search');
});

test('drill-down to alerts opens Summary filtered to that priority and highlights the alert panel', async () => {
    const f = bootDashboard({ ids: [...TAB_PANELS, 'alerts-list', 'select:alert-severity-filter', 'panel-alerts'] });
    await settle();
    const tab = tabBar(f);
    tab('alerts').click();
    const drill = f.context.drillDown, panel = f.el('panel-alerts'), filter = f.el('alert-severity-filter'), picked = [];
    filter.addEventListener('change', () => picked.push(filter.value));
    const before = f.requests.length;
    drill.toAlerts('critical');
    await f.tick(ARRIVED);
    assert.deepEqual([activeTab(f), filter.value, picked], ['summary', 'critical', ['critical']]);
    assert.ok(f.requests.slice(before).some(call => /^\/api\/alerts\/\?severity=critical&_t=\d+$/.test(call.url)), 'the alert list reloads for that priority');
    assert.deepEqual([panel.classList.contains('drilldown-highlight'), panel.scrolledIntoView], [true, true]);
    await f.tick(FADED);
    assert.equal(panel.classList.contains('drilldown-highlight'), false);
    drill.toAlerts();
    await f.tick(ARRIVED);
    assert.deepEqual(picked, ['critical'], 'no priority, no filter change');
    assert.equal(panel.classList.contains('drilldown-highlight'), true);
});
