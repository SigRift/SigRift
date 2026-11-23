/* The admin console's Alerts, Audit Log and Training tabs (admin.js):
 * condition rules and legacy alert rules, the filtered and paged audit log
 * with its detail view, and training run health, driven through the
 * controls of templates/admin.html in the admin_dom.cjs stub DOM. */
const assert = require('node:assert/strict');
const test = require('node:test');
const { adminPage, noUnexpectedConsoleErrors, reply, FakeEvent, assertCookieWrite, call, cell } = require('./admin_dom.cjs');

test.afterEach(noUnexpectedConsoleErrors);

const lastToast = page => page.toasts().at(-1);
const gets = (page, url) => page.requests.filter(r => r.method === 'GET' && r.url === url).length;

/* ------------------------------------------------------------------ */
/* Condition rules                                                     */
/* ------------------------------------------------------------------ */

async function alertsTab({ rules = [], alerts = [], routes = {} } = {}) {
    const server = { rules, alerts };
    const page = await adminPage({
        routes: {
            'GET /api/admin/alerts': () => reply(200, server.alerts),
            'GET /api/alerts/rules/conditions': () => reply(200, server.rules),
            ...routes,
        },
    });
    page.server = server;
    await page.tab('alerts');
    return page;
}

const ruleForm = page => ({
    shown: page.byId('condition-rule-form').style.display,
    edit: page.byId('condition-rule-edit-id').value,
    name: page.byId('condition-rule-name').value,
    severity: page.byId('condition-rule-severity').value,
    cooldown: page.byId('condition-rule-cooldown').value,
    enabled: page.byId('condition-rule-enabled').checked,
    webhook: page.byId('condition-rule-webhook').checked,
    rows: page.byId('condition-rows').children.map(row => [
        row.querySelector('.cond-field').value, row.querySelector('.cond-op').value, row.querySelector('.cond-val').value]),
});
function setRow(row, fieldName, operator, value) {
    row.querySelector('.cond-field').value = fieldName;
    row.querySelector('.cond-op').value = operator;
    row.querySelector('.cond-val').value = value;
}

test('a new condition rule starts from the defaults with one empty condition; conditions can be added and removed', async () => {
    const page = await alertsTab();
    assert.equal(page.byId('condition-rules-empty').style.display, '');
    page.byId('condition-rule-name').value = 'left over';
    page.byId('condition-rule-enabled').checked = false;
    await page.click(page.byId('admin-create-condition-rule-btn'));
    assert.deepEqual(ruleForm(page), {
        shown: '', edit: '', name: '', severity: 'warning', cooldown: '300', enabled: true, webhook: true,
        rows: [['signal_class', 'eq', '']],
    });
    await page.click(page.byId('add-condition-row-btn'));
    await page.click(page.byId('add-condition-row-btn'));
    assert.equal(page.byId('condition-rows').children.length, 3);
    const [, second] = page.byId('condition-rows').children;
    setRow(second, 'snr_db', 'gt', '12');
    await page.click(second.querySelector('.cond-remove'));
    assert.deepEqual(ruleForm(page).rows, [['signal_class', 'eq', ''], ['signal_class', 'eq', '']]);
    await page.click(page.byId('condition-rule-cancel-btn'));
    assert.equal(page.byId('condition-rule-form').style.display, 'none');
    assert.deepEqual(page.writes(), []);
});

test('saving a new condition rule converts each value by its operator', async () => {
    let refuse = false;
    const page = await alertsTab({
        routes: {
            'POST /api/alerts/rules/conditions': request => {
                if (refuse) return reply(422, { detail: 'unknown field' });
                page.server.rules = [{ rule_id: 'cr_1', ...request.body }];
                return reply(201, {});
            },
        },
    });
    await page.click(page.byId('admin-create-condition-rule-btn'));
    await page.click(page.byId('condition-rule-save-btn'));
    assert.deepEqual(lastToast(page), { text: 'Rule name is required', type: 'error', markup: 0 });
    assert.equal(page.doc.activeElement, page.byId('condition-rule-name'));
    assert.deepEqual(page.writes(), []);

    page.byId('condition-rule-name').value = '  High-power BPSK  ';
    page.byId('condition-rule-severity').value = 'critical';
    page.byId('condition-rule-cooldown').value = 'soon';
    page.byId('condition-rule-enabled').checked = false;
    page.byId('condition-rule-webhook').checked = false;
    for (let i = 0; i < 4; i++) await page.click(page.byId('add-condition-row-btn'));
    const rows = page.byId('condition-rows').children;
    setRow(rows[0], 'freq_hz', 'gt', ' 433920000 ');
    setRow(rows[1], 'signal_class', 'eq', 'bpsk');
    setRow(rows[2], 'node_id', 'in', ' edge-1, edge-2 ');
    setRow(rows[3], 'snr_db', 'between', '3, 9.5');
    setRow(rows[4], 'family', 'not_in', 'wifi');
    await page.click(page.byId('condition-rule-save-btn'));
    const [created] = page.writes();
    assert.deepEqual(call(created), ['POST', '/api/alerts/rules/conditions', {
        name: 'High-power BPSK', severity: 'critical', enabled: false, cooldown_seconds: 300, notify_webhook: false,
        conditions: [
            { field: 'freq_hz', operator: 'gt', value: 433920000 },
            { field: 'signal_class', operator: 'eq', value: 'bpsk' },
            { field: 'node_id', operator: 'in', value: ['edge-1', 'edge-2'] },
            { field: 'snr_db', operator: 'between', value: [3, 9.5] },
            { field: 'family', operator: 'not_in', value: ['wifi'] },
        ],
    }]);
    assertCookieWrite(created);
    assert.equal(page.byId('condition-rule-form').style.display, 'none');
    assert.deepEqual(lastToast(page), { text: 'Rule created', type: 'success', markup: 0 });
    assert.equal(cell(page.byId('condition-rules-tbody'), 'Rule ID').textContent, 'cr_1', 'the rule list is reloaded');

    refuse = true;
    await page.click(page.byId('admin-create-condition-rule-btn'));
    page.byId('condition-rule-name').value = 'Another';
    page.byId('condition-rule-cooldown').value = '60';
    setRow(page.byId('condition-rows').children[0], 'signal_class', 'eq', 'fsk');
    await page.click(page.byId('condition-rule-save-btn'));
    assert.deepEqual(page.writes()[1].body.cooldown_seconds, 60);
    assert.deepEqual(lastToast(page), { text: 'Failed to create rule: unknown field', type: 'error', markup: 0 });
    assert.equal(page.byId('condition-rule-form').style.display, '', 'a refused rule keeps the form open');
});

test('a condition whose value is left blank is not saved as the number 0', async () => {
    const page = await alertsTab({ routes: { 'POST /api/alerts/rules/conditions': () => reply(201, {}) } });
    await page.click(page.byId('admin-create-condition-rule-btn'));
    page.byId('condition-rule-name').value = 'Forgot the value';
    await page.click(page.byId('condition-rule-save-btn'));
    const sent = page.writes().map(request => request.body.conditions);
    assert.notDeepEqual(sent, [[{ field: 'signal_class', operator: 'eq', value: 0 }]]);
});

test('a rule is not saved with a blank condition row or without conditions; the admin is told which row', async () => {
    const page = await alertsTab({ routes: { 'POST /api/alerts/rules/conditions': () => reply(201, {}) } });
    await page.click(page.byId('admin-create-condition-rule-btn'));
    page.byId('condition-rule-name').value = 'Mixed';
    await page.click(page.byId('condition-rule-save-btn'));
    assert.deepEqual(lastToast(page), { text: 'Condition 1 has no value: enter one or remove the row', type: 'error', markup: 0 },
        'the empty row a new rule starts with is not a rule that never fires');
    assert.equal(page.doc.activeElement, page.byId('condition-rows').children[0].querySelector('.cond-val'));
    assert.equal(page.byId('condition-rule-form').style.display, '', 'the form stays open');

    for (let i = 0; i < 4; i++) await page.click(page.byId('add-condition-row-btn'));
    let rows = page.byId('condition-rows').children;
    setRow(rows[0], 'snr_db', 'gte', '0');
    for (const [index, operator, blank] of [[1, 'gt', '   '], [2, 'in', ''], [3, 'between', ''], [4, 'lt', '']]) {
        setRow(rows[index], 'power_dbm', operator, blank);
    }
    await page.click(page.byId('condition-rule-save-btn'));
    assert.deepEqual(lastToast(page), { text: 'Condition 2 has no value: enter one or remove the row', type: 'error', markup: 0 },
        'a cleared AND condition is not dropped silently, which would broaden the rule');
    assert.equal(page.doc.activeElement, rows[1].querySelector('.cond-val'));

    while (page.byId('condition-rows').children.length) {
        await page.click(page.byId('condition-rows').children[0].querySelector('.cond-remove'));
    }
    await page.click(page.byId('condition-rule-save-btn'));
    assert.deepEqual(lastToast(page), { text: 'Add at least one condition', type: 'error', markup: 0 });
    assert.deepEqual(page.writes(), []);

    await page.click(page.byId('add-condition-row-btn'));
    rows = page.byId('condition-rows').children;
    setRow(rows[0], 'snr_db', 'gte', '0');
    await page.click(page.byId('condition-rule-save-btn'));
    assert.deepEqual(page.writes().map(request => request.body.conditions), [[{ field: 'snr_db', operator: 'gte', value: 0 }]],
        'a typed 0 is kept');
});

const RULE = {
    rule_id: 'cr/1', name: 'Tx and Rx', severity: 'info', cooldown_seconds: 120, enabled: false, notify_webhook: false,
    trigger_count: 5, last_triggered_at: '2026-11-10T11:00:00Z',
    conditions: [{ field: 'node_id', operator: 'in', value: ['edge-1', 'edge-2'] }, { field: 'power_dbm', operator: 'gte', value: -40 }],
};
const BARE_RULE = { rule_id: 'cr2', name: 'Bare', enabled: true };

test('editing a condition rule fills the form from the stored rule and saves it to that rule', async () => {
    let refuse = false;
    const page = await alertsTab({
        rules: [RULE, BARE_RULE],
        routes: {
            'PUT /api/alerts/rules/conditions/cr%2F1': () => (refuse ? reply(500) : reply(200, {})),
            'PUT /api/alerts/rules/conditions/cr2': () => reply(200, {}),
        },
    });
    const edit = id => page.click(page.byId('condition-rules-tbody').querySelector('[data-edit-crule="' + id + '"]'));
    await edit('cr/1');
    assert.deepEqual(ruleForm(page), {
        shown: '', edit: 'cr/1', name: 'Tx and Rx', severity: 'info', cooldown: '120', enabled: false, webhook: false,
        rows: [['node_id', 'in', 'edge-1,edge-2'], ['power_dbm', 'gte', '-40']],
    });
    await page.click(page.byId('condition-rule-save-btn'));
    const [update] = page.writes();
    assert.deepEqual(call(update), ['PUT', '/api/alerts/rules/conditions/cr%2F1', {
        name: 'Tx and Rx', severity: 'info', enabled: false, cooldown_seconds: 120, notify_webhook: false,
        conditions: [{ field: 'node_id', operator: 'in', value: ['edge-1', 'edge-2'] }, { field: 'power_dbm', operator: 'gte', value: -40 }],
    }]);
    assertCookieWrite(update);
    assert.deepEqual(lastToast(page), { text: 'Rule updated', type: 'success', markup: 0 });
    assert.equal(page.byId('condition-rule-form').style.display, 'none');

    // A rule stored without severity, cooldown or conditions opens with the defaults and one empty condition.
    await edit('cr2');
    assert.deepEqual(ruleForm(page), {
        shown: '', edit: 'cr2', name: 'Bare', severity: 'warning', cooldown: '300', enabled: true, webhook: true,
        rows: [['signal_class', 'eq', '']],
    });
    // It never fires as stored, so saving it again needs a condition.
    await page.click(page.byId('condition-rule-save-btn'));
    assert.deepEqual(lastToast(page), { text: 'Condition 1 has no value: enter one or remove the row', type: 'error', markup: 0 });
    assert.equal(page.writes().length, 1);
    setRow(page.byId('condition-rows').children[0], 'signal_class', 'eq', 'ook');
    await page.click(page.byId('condition-rule-save-btn'));
    assert.equal(page.writes()[1].url, '/api/alerts/rules/conditions/cr2');
    assert.deepEqual(page.writes()[1].body.conditions, [{ field: 'signal_class', operator: 'eq', value: 'ook' }]);

    await edit('cr/1');
    refuse = true;
    await page.click(page.byId('condition-rule-save-btn'));
    assert.deepEqual(lastToast(page), { text: 'Failed to update rule: HTTP 500', type: 'error', markup: 0 });

    // A New rule after an edit is created, not saved over the edited one.
    await page.click(page.byId('admin-create-condition-rule-btn'));
    assert.equal(page.byId('condition-rule-edit-id').value, '');
});

test('the condition rule list joins conditions with AND and fills in defaults for missing fields', async () => {
    const page = await alertsTab({ rules: [RULE, BARE_RULE] });
    const [first, second] = page.byId('condition-rules-tbody').querySelectorAll('tr');
    const read = row => ['Conditions', 'Enabled', 'Cooldown', 'Triggers'].map(label => cell(row, label).textContent);
    assert.deepEqual(read(first), ['node_id in edge-1,edge-2 AND power_dbm gte -40', 'No', '120s', '5']);
    assert.deepEqual(read(second), ['no conditions', 'Yes', '300s', '0']);
    assert.equal(cell(first, 'Last Triggered').textContent, page.context.fmtTime(RULE.last_triggered_at));
    assert.equal(cell(second, 'Last Triggered').textContent, '--');
    assert.match(cell(second, 'Severity').textContent, /warning$/);
    assert.equal(page.byId('condition-rules-empty').style.display, 'none');
});

test('testing a condition rule runs a dry run over the last hour and reports the matches', async () => {
    let answer = () => reply(200, { detections_scanned: 1000, matches: 7 });
    const page = await alertsTab({ rules: [RULE], routes: { 'POST /api/alerts/rules/conditions/cr%2F1/test': () => answer() } });
    await page.click(page.byId('condition-rules-tbody').querySelector('[data-test-crule="cr/1"]'));
    assert.deepEqual(call(page.writes()[0]), ['POST', '/api/alerts/rules/conditions/cr%2F1/test', { minutes: 60, limit: 1000 }]);
    const modal = page.modal();
    assert.equal(modal.querySelector('.admin-modal-title').textContent, 'Dry-run results — rule cr/1');
    assert.equal(modal.querySelector('.admin-modal-body').textContent, 'Detections scanned: 1000Matches: 7');
    await page.click(page.button('Close'));
    assert.equal(page.modal(), null);

    answer = () => reply(400, { detail: 'rule has no conditions' });
    await page.click(page.byId('condition-rules-tbody').querySelector('[data-test-crule="cr/1"]'));
    assert.equal(page.modal(), null);
    assert.deepEqual(lastToast(page), { text: 'Test failed: rule has no conditions', type: 'error', markup: 0 });
});

test('deleting a condition rule needs confirmation; a refusal says why', async () => {
    let refuse = true;
    const page = await alertsTab({
        rules: [RULE],
        routes: { 'DELETE /api/alerts/rules/conditions/cr%2F1': () => (refuse ? reply(423, { detail: 'rule locked' }) : reply(204)) },
    });
    const remove = () => page.click(page.byId('condition-rules-tbody').querySelector('[data-del-crule="cr/1"]'));
    await remove();
    assert.equal(page.modal().textContent.includes('Delete condition rule cr/1?'), true);
    await page.click(page.button('Cancel'));
    assert.deepEqual(page.writes(), []);
    await remove();
    await page.click(page.button('Delete'));
    assert.deepEqual(lastToast(page), { text: 'Failed to delete rule: rule locked', type: 'error', markup: 0 });
    refuse = false;
    page.server.rules = [];
    await remove();
    await page.click(page.button('Delete'));
    assert.deepEqual(lastToast(page), { text: 'Rule deleted', type: 'success', markup: 0 });
    assert.deepEqual(page.writes().map(call), Array(2).fill(['DELETE', '/api/alerts/rules/conditions/cr%2F1', undefined]));
    assert.equal(page.byId('condition-rules-empty').style.display, '');
});

/* ------------------------------------------------------------------ */
/* Legacy alert rules                                                  */
/* ------------------------------------------------------------------ */

test('legacy alert rules: the list shows severity and acknowledgement; Create stays disabled until a name is typed', async () => {
    const page = await alertsTab({
        alerts: [
            { alert_id: 'al/1', name: 'Jammer', severity: 'high', message: 'Tx and Rx', triggered_at: '2026-11-10T11:00:00Z', acknowledged: true },
            { alert_id: 'al2', name: 'Quiet' },
        ],
        routes: { 'POST /api/admin/alerts': request => { page.server.alerts = [{ alert_id: 'al3', ...request.body }]; return reply(201, {}); } },
    });
    const [first, second] = page.byId('admin-alerts-tbody').querySelectorAll('tr');
    const read = row => ['Name', 'Message', 'Ack'].map(label => cell(row, label).textContent);
    assert.deepEqual(read(first), ['Jammer', 'Tx and Rx', 'Yes']);
    assert.deepEqual(read(second), ['Quiet', '--', 'No']);
    assert.match(cell(first, 'Severity').textContent, /high$/);
    assert.match(cell(second, 'Severity').textContent, /info$/);
    assert.equal(page.byId('admin-alerts-empty').style.display, 'none');

    await page.click(page.byId('admin-create-alert-btn'));
    const create = page.button('Create'), name = page.modal().querySelector('#admin-modal-alert-name');
    assert.equal(page.doc.activeElement, name);
    assert.equal(create.disabled, true);
    await page.input(name, '   ');
    assert.equal(create.disabled, true);
    await page.click(page.button('Cancel'));
    assert.deepEqual(page.writes(), []);

    await page.click(page.byId('admin-create-alert-btn'));
    await page.input(page.modal().querySelector('#admin-modal-alert-name'), ' Drone uplink ');
    assert.equal(page.button('Create').disabled, false);
    assert.equal(page.modal().querySelector('#admin-modal-alert-severity').value, 'warning');
    page.modal().querySelector('#admin-modal-alert-severity').value = 'critical';
    await page.click(page.button('Create'));
    assert.equal(page.modal(), null);
    const [created] = page.writes();
    assert.deepEqual(call(created), ['POST', '/api/admin/alerts', { name: 'Drone uplink', severity: 'critical', thresholds: {} }]);
    assertCookieWrite(created);
    assert.equal(cell(page.byId('admin-alerts-tbody'), 'Name').textContent, 'Drone uplink', 'the list is reloaded');
});

test('deleting a legacy alert rule needs confirmation; a refusal says why', async () => {
    let refuse = true;
    const page = await alertsTab({
        alerts: [{ alert_id: 'al/1', name: 'Jammer' }],
        routes: { 'DELETE /api/admin/alerts/al%2F1': () => (refuse ? reply(404) : reply(204)) },
    });
    const remove = () => page.click(page.byId('admin-alerts-tbody').querySelector('[data-del-alert="al/1"]'));
    await remove();
    await page.click(page.button('Cancel'));
    await remove();
    await page.click(page.button('Delete'));
    assert.deepEqual(lastToast(page), { text: 'Failed to delete alert: HTTP 404', type: 'error', markup: 0 });
    refuse = false;
    page.server.alerts = [];
    await remove();
    await page.click(page.button('Delete'));
    assert.deepEqual(lastToast(page), { text: 'Alert deleted', type: 'success', markup: 0 });
    assert.equal(page.writes().length, 2);
    assert.equal(page.byId('admin-alerts-empty').style.display, '');
});

/* ------------------------------------------------------------------ */
/* Audit log                                                           */
/* ------------------------------------------------------------------ */

const entry = (i, extra = {}) => ({ timestamp: '2026-11-10T11:00:00Z', action: 'key_create', target_id: 'key_' + i, operator: 'admin', ...extra });

async function auditTab({ entries = () => [], filters = { actions: [], operators: [], node_ids: [] }, routes = {} } = {}) {
    const page = await adminPage({
        routes: {
            'GET /api/admin/audit/filters': () => reply(200, filters),
            'GET /api/admin/audit': request => reply(200, { entries: entries(new URL(request.url, 'https://bridge.test').searchParams) }),
            ...routes,
        },
    });
    await page.tab('audit');
    return page;
}
const auditReads = page => page.requests.filter(r => r.url.startsWith('/api/admin/audit?') || r.url.startsWith('/api/training/operations'))
    .map(r => r.url);

test('audit filters are offered from the server once and sent as query parameters from the first page', async () => {
    const page = await auditTab({ filters: { actions: ['training', 'key_create', 'node_deregister'], operators: ['admin', 'ops'], node_ids: ['edge-1'] } });
    assert.deepEqual(page.byId('audit-action-filter').options.map(o => o.value), ['', 'training', 'key_create', 'node_deregister'],
        'an action the page already offers is not added twice');
    assert.deepEqual(page.byId('audit-operator-filter').options.map(o => o.value), ['', 'admin', 'ops']);
    assert.deepEqual(page.byId('audit-node-filter').options.map(o => o.value), ['', 'edge-1']);
    assert.deepEqual(auditReads(page), ['/api/admin/audit?limit=50&offset=0']);

    await page.change(page.byId('audit-action-filter'), 'key_create');
    await page.change(page.byId('audit-operator-filter'), 'ops');
    await page.change(page.byId('audit-node-filter'), 'edge-1');
    await page.change(page.byId('audit-severity-filter'), 'critical');
    page.byId('audit-search-filter').value = 'rotate key';
    await page.key('a', page.byId('audit-search-filter'));
    await page.key('Enter', page.byId('audit-search-filter'));
    page.byId('audit-start-filter').value = '2026-11-09T08:00';
    page.byId('audit-end-filter').value = '2026-11-10T08:30';
    await page.click(page.byId('audit-filter-btn'));
    const start = encodeURIComponent(new Date('2026-11-09T08:00').toISOString());
    const end = encodeURIComponent(new Date('2026-11-10T08:30').toISOString());
    assert.deepEqual(auditReads(page).slice(1), [
        '/api/admin/audit?limit=50&offset=0&action=key_create',
        '/api/admin/audit?limit=50&offset=0&action=key_create&operator=ops',
        '/api/admin/audit?limit=50&offset=0&action=key_create&operator=ops&node_id=edge-1',
        '/api/admin/audit?limit=50&offset=0&action=key_create&operator=ops&node_id=edge-1&severity=critical',
        '/api/admin/audit?limit=50&offset=0&action=key_create&operator=ops&node_id=edge-1&search=rotate%20key&severity=critical',
        '/api/admin/audit?limit=50&offset=0&action=key_create&operator=ops&node_id=edge-1&search=rotate%20key&start=' + start + '&end=' + end + '&severity=critical',
    ], 'other keys in the search box do not reload');

    await page.click(page.byId('audit-clear-btn'));
    for (const id of ['audit-action-filter', 'audit-operator-filter', 'audit-node-filter', 'audit-severity-filter',
        'audit-search-filter', 'audit-start-filter', 'audit-end-filter']) assert.equal(page.byId(id).value, '', id);
    assert.equal(auditReads(page).at(-1), '/api/admin/audit?limit=50&offset=0');

    await page.tab('keys');
    await page.tab('audit');
    assert.equal(gets(page, '/api/admin/audit/filters'), 1, 'the filter lists are fetched once');
    assert.deepEqual(page.byId('audit-action-filter').options.map(o => o.value), ['', 'training', 'key_create', 'node_deregister']);
});

test('audit paging: Next moves on a page of 50, Prev goes back, and each is disabled at its end', async () => {
    const page = await auditTab({
        entries: params => Array.from({ length: Number(params.get('offset')) >= 100 ? 3 : 50 }, (_, i) => entry(Number(params.get('offset')) + i)),
    });
    const prev = page.byId('audit-prev-btn'), next = page.byId('audit-next-btn');
    const state = () => [prev.disabled, next.disabled, page.byId('audit-tbody').querySelectorAll('tr').length,
        cell(page.byId('audit-tbody'), 'Target').textContent];
    assert.deepEqual(state(), [true, false, 50, 'key_0']);
    await page.click(next);
    assert.deepEqual(state(), [false, false, 50, 'key_50']);
    await page.click(next);
    assert.deepEqual(state(), [false, true, 3, 'key_100']);
    await page.click(prev);
    assert.deepEqual(state(), [false, false, 50, 'key_50']);
    await page.click(page.byId('audit-filter-btn'));
    assert.deepEqual(state(), [true, false, 50, 'key_0'], 'a new filter starts from the first page');
    assert.deepEqual(auditReads(page).map(url => new URL(url, 'https://bridge.test').searchParams.get('offset')), ['0', '50', '100', '50', '0']);
});

test('the Training action reads the training operations log, which has no paging', async () => {
    const page = await auditTab({
        entries: () => [entry(1)],
        routes: { 'GET /api/training/operations': () => reply(200, [entry(9, { action: 'training_start' })]) },
    });
    await page.change(page.byId('audit-action-filter'), 'training');
    assert.equal(auditReads(page).at(-1), '/api/training/operations?limit=50');
    assert.equal(cell(page.byId('audit-tbody'), 'Action').textContent, 'training_start');
    assert.deepEqual([page.byId('audit-prev-btn').disabled, page.byId('audit-next-btn').disabled], [true, true]);

    page.routes['GET /api/training/operations'] = () => reply(200, null);
    await page.click(page.byId('audit-filter-btn'));
    assert.equal(page.byId('audit-tbody').innerHTML, '');
    assert.equal(page.byId('audit-empty').style.display, '');
});

const DETAILED = [
    entry(1, { action: 'bulk_dismiss', target_ids: ['wifi_1', 'wifi_2', 'wifi_3'], operator: null, freq_hz: 433920000, signal_class: 'ook',
        node_id: 'edge-1', note: 'cleanup',
        details: { reason: 'x'.repeat(50), severity: 'critical', filter: { band: '433' }, count: 3, dry_run: false } }),
    entry(2, { action: 'note_only', details: {} }),
    entry(3, { action: 'config_change', details: { severity: 'warning', changes: [{ key: 'retention', old: 30, new: 7 }, { key: 'banner', old: null, new: 'x' }] } }),
    entry(4, { action: 'login', details: { changes: [{ key: 'k', old: 1, new: null }] } }),
];

test('audit rows preview their details and mark their severity', async () => {
    const page = await auditTab({ entries: () => DETAILED });
    const rows = page.byId('audit-tbody').querySelectorAll('tr');
    assert.deepEqual(rows.map(row => cell(row, 'Details').textContent), [
        'reason: ' + 'x'.repeat(37) + '...; severity: critical; filter: {"band":"433"} +2 more View', '--', '2 changes View', '1 change View']);
    assert.deepEqual(rows.map(row => cell(row, 'Sev').textContent), ['critical', 'info', 'warning', 'info']);
    assert.deepEqual(rows.map(row => row.className), ['audit-sev-critical', '', 'audit-sev-warning', ''].map(name => name && ' ' + name));
    assert.deepEqual(rows.map(row => cell(row, 'Operator').textContent), ['--', 'admin', 'admin', 'admin']);
    assert.equal(rows[1].querySelector('[data-audit-idx]'), null, 'an entry without details has nothing to view');
});

test('the audit detail view shows every field, and closes by its buttons, a click outside or Escape', async () => {
    const page = await auditTab({ entries: () => DETAILED });
    const modal = page.byId('audit-detail-modal'), body = page.byId('audit-detail-body');
    const view = index => page.click(page.byId('audit-tbody').querySelector('[data-audit-idx="' + index + '"]'));
    const fields = () => Object.fromEntries(body.querySelector('table').querySelectorAll('tr').map(tr => [tr.children[0].textContent, tr.children[1].textContent]));

    await view(0);
    assert.equal(modal.style.display, '');
    assert.equal(page.doc.activeElement, modal);
    assert.deepEqual(fields(), {
        Timestamp: '2026-11-10T11:00:00Z', Action: 'bulk_dismiss', 'Target ID': 'key_1', Operator: '--', 'Node ID': 'edge-1',
        'Signal Class': 'ook', Frequency: '433.920 MHz', Note: 'cleanup', 'Targets (3)': 'wifi_1, wifi_2, wifi_3',
    });
    assert.equal(body.querySelector('pre').textContent, JSON.stringify(DETAILED[0].details, null, 2));
    await page.click(page.byId('audit-detail-close'));
    assert.equal(modal.style.display, 'none');

    await view(2);
    assert.deepEqual(fields(), {
        Timestamp: '2026-11-10T11:00:00Z', Action: 'config_change', 'Target ID': 'key_3', Operator: 'admin', 'Node ID': '--',
        'Signal Class': '--', Frequency: '--', Note: '--',
    });
    const changes = body.querySelectorAll('table')[1].querySelectorAll('tbody tr').map(tr => tr.children.map(td => td.textContent));
    assert.deepEqual(changes, [['retention', '30', '7'], ['banner', 'null', 'x']]);
    await page.click(page.byId('audit-detail-dismiss'));
    assert.equal(modal.style.display, 'none');

    await view(3);
    modal.dispatchEvent(new FakeEvent('click', { target: body }));
    assert.equal(modal.style.display, '', 'a click inside the dialog keeps it open');
    modal.dispatchEvent(new FakeEvent('click'));
    assert.equal(modal.style.display, 'none', 'a click on the backdrop closes it');

    await view(0);
    await page.key('Enter');
    assert.equal(modal.style.display, '');
    await page.key('Escape');
    assert.equal(modal.style.display, 'none');
});

test('Copy JSON copies the whole audit entry and confirms on the button', async () => {
    const page = await auditTab({ entries: () => DETAILED });
    await page.click(page.byId('audit-tbody').querySelector('[data-audit-idx="2"]'));
    const copy = page.byId('audit-detail-copy');
    await page.click(copy);
    assert.deepEqual(page.clipboard, [JSON.stringify(DETAILED[2], null, 2)]);
    assert.equal(copy.textContent, 'Copied!');
    await page.advance(1500);
    assert.equal(copy.textContent, 'Copy JSON');
});

/* ------------------------------------------------------------------ */
/* Training                                                            */
/* ------------------------------------------------------------------ */

test('training tab: one health card per run, and the training operations log', async () => {
    let health = () => reply(200, {
        runs: [
            { run_id: 'run_a', status: 'active', current_epoch: 3, best_val_acc: 0.9125, last_activity_s: 93784 },
            { run_id: 'run_b', status: 'stalled', current_epoch: 0, last_activity_s: 59 },
            { run_id: 'run_c', status: 'failed' }, { run_id: 'run_d', status: 'completed' }, { run_id: 'run_e', status: 'queued' }, { run_id: 'run_f' },
        ],
    });
    let ops = () => reply(200, [entry(1, { action: 'training_start', details: { epochs: 10 } })]);
    const page = await adminPage({ routes: { 'GET /api/training/health': () => health(), 'GET /api/training/operations': () => ops() } });
    await page.tab('training');
    const cards = () => page.byId('training-health-cards').querySelectorAll('.metric-card').map(card => card.textContent);
    assert.deepEqual(cards(), [
        'activerun_aEpoch 3 | Acc 91.3%Last: 1d 2h 3m ago',
        'stalledrun_bEpoch 0 | Acc --Last: 0m ago',
        'failedrun_cEpoch -- | Acc --Last: --', 'completedrun_dEpoch -- | Acc --Last: --',
        'queuedrun_eEpoch -- | Acc --Last: --', 'unknownrun_fEpoch -- | Acc --Last: --',
    ]);
    const colors = page.byId('training-health-cards').querySelectorAll('.metric-value').map(el => el.style.color);
    assert.deepEqual(colors, ['var(--accent-green)', 'var(--accent-yellow)', 'var(--accent-red)', 'var(--accent-cyan)',
        'var(--text-secondary)', 'var(--text-secondary)']);
    assert.equal(page.byId('training-health-empty').style.display, 'none');
    assert.equal(cell(page.byId('training-ops-tbody'), 'Action').textContent, 'training_start');
    assert.equal(page.byId('training-ops-empty').style.display, 'none');

    health = () => reply(200, { runs: [] });
    await page.click(page.byId('training-health-refresh'));
    assert.deepEqual(cards(), []);
    assert.equal(page.byId('training-health-empty').style.display, '');

    health = () => reply(503);
    ops = () => reply(200, []);
    await page.tab('training');
    assert.equal(page.byId('training-health-cards').textContent, 'Failed to load training health');
    assert.equal(page.byId('training-ops-tbody').innerHTML, '');
    assert.equal(page.byId('training-ops-empty').style.display, '');
});

test('a condition rule change refused without an explanation reports its HTTP status', async () => {
    const page = await alertsTab({
        rules: [RULE],
        routes: {
            'POST /api/alerts/rules/conditions': () => reply(500),
            'DELETE /api/alerts/rules/conditions/cr%2F1': () => reply(500),
            'POST /api/alerts/rules/conditions/cr%2F1/test': () => reply(500),
        },
    });
    await page.click(page.byId('admin-create-condition-rule-btn'));
    page.byId('condition-rule-name').value = 'Rule';
    setRow(page.byId('condition-rows').children[0], 'signal_class', 'eq', 'fsk');
    await page.click(page.byId('condition-rule-save-btn'));
    assert.deepEqual(lastToast(page), { text: 'Failed to create rule: HTTP 500', type: 'error', markup: 0 });
    await page.click(page.byId('condition-rules-tbody').querySelector('[data-test-crule="cr/1"]'));
    assert.deepEqual(lastToast(page), { text: 'Test failed: HTTP 500', type: 'error', markup: 0 });
    await page.click(page.byId('condition-rules-tbody').querySelector('[data-del-crule="cr/1"]'));
    await page.click(page.button('Delete'));
    assert.deepEqual(lastToast(page), { text: 'Failed to delete rule: HTTP 500', type: 'error', markup: 0 });
});
