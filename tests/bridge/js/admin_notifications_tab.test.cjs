/* The admin console's Notifications tab (admin.js): webhook endpoints, their
 * delivery log, and syslog forwarding targets, driven through the controls
 * of templates/admin.html in the admin_dom.cjs stub DOM. */
const assert = require('node:assert/strict');
const test = require('node:test');
const { adminPage, noUnexpectedConsoleErrors, reply, assertCookieWrite, assertInert, MARKUP, ATTR_MARKUP, call, cell } = require('./admin_dom.cjs');

test.afterEach(noUnexpectedConsoleErrors);

const chosen = select => select.options.filter(option => option.selected).map(option => option.value);
const choose = (select, values) => { for (const option of select.options) option.selected = values.includes(option.value); };
const lastToast = page => page.toasts().at(-1);
const gets = (page, url) => page.requests.filter(r => r.method === 'GET' && r.url === url).length;

/* A notifications tab whose server holds `webhooks`, `log` and `targets`
 * (mutable through `page.server`), plus any extra routes. */
async function notificationsTab({ webhooks = [], log = [], targets = [], routes = {} } = {}) {
    const server = { webhooks, log, targets };
    const page = await adminPage({
        routes: {
            'GET /api/admin/webhooks': () => reply(200, { webhooks: server.webhooks, delivery_log: server.log }),
            'GET /api/admin/syslog': () => reply(200, { targets: server.targets }),
            ...routes,
        },
    });
    page.server = server;
    await page.tab('notifications');
    return page;
}

/* ------------------------------------------------------------------ */
/* Webhooks                                                            */
/* ------------------------------------------------------------------ */

test('adding a webhook: the form opens empty with every severity chosen; a blank URL is refused; the chosen severities are sent', async () => {
    let refuse = false;
    const page = await notificationsTab({
        routes: {
            'POST /api/admin/webhooks': request => {
                if (refuse) return reply(422, { detail: 'URL must use https' });
                page.server.webhooks.push({ id: 'wh_' + page.server.webhooks.length, enabled: true, ...request.body });
                return reply(201, {});
            },
        },
    });
    const form = page.byId('admin-webhook-form'), url = page.byId('webhook-url-input'), name = page.byId('webhook-name-input');
    const severity = page.byId('webhook-severity-input');
    assert.equal(page.byId('admin-webhooks-empty').style.display, '');
    assert.equal(page.byId('admin-webhooks-table').style.display, 'none');
    assert.equal(form.style.display, 'none');

    url.value = 'left over'; name.value = 'left over'; choose(severity, []);
    await page.click(page.byId('admin-add-webhook-btn'));
    assert.deepEqual([form.style.display, url.value, name.value, chosen(severity)], ['', '', '', ['critical', 'warning']]);
    assert.equal(page.doc.activeElement, url, 'the URL field has focus');

    await page.input(url, '   ');
    await page.click(page.byId('webhook-save-btn'));
    assert.deepEqual(page.writes(), []);
    assert.deepEqual(lastToast(page), { text: 'URL is required.', type: 'error', markup: 0 });

    url.value = ' https://hooks.example/a ';
    name.value = ' Ops room ';
    choose(severity, ['critical']);
    await page.click(page.byId('webhook-save-btn'));
    const [created] = page.writes();
    assert.deepEqual(call(created), ['POST', '/api/admin/webhooks', { url: 'https://hooks.example/a', name: 'Ops room', severity_filter: ['critical'] }]);
    assertCookieWrite(created);
    assert.equal(form.style.display, 'none');
    assert.deepEqual(lastToast(page), { text: 'Webhook created', type: 'success', markup: 0 });
    assert.equal(cell(page.byId('admin-webhooks-tbody'), 'Name').textContent, 'Ops room', 'the list is reloaded');
    assert.equal(page.byId('admin-webhooks-empty').style.display, 'none');
    assert.equal(page.byId('admin-webhooks-table').style.display, '');

    // Nothing chosen: the server's default filter (critical and warning) is sent.
    await page.click(page.byId('admin-add-webhook-btn'));
    url.value = 'https://hooks.example/b';
    choose(severity, []);
    await page.click(page.byId('webhook-save-btn'));
    assert.deepEqual(page.writes()[1].body, { url: 'https://hooks.example/b', name: '', severity_filter: ['critical', 'warning'] });

    refuse = true;
    await page.click(page.byId('admin-add-webhook-btn'));
    url.value = 'http://plain.example';
    await page.click(page.byId('webhook-save-btn'));
    assert.deepEqual(lastToast(page), { text: 'Failed to create webhook: URL must use https', type: 'error', markup: 0 });
    assert.equal(form.style.display, '', 'a refused webhook keeps the form open');
    await page.click(page.byId('webhook-cancel-btn'));
    assert.equal(form.style.display, 'none');
});

const SLACK = { id: 'wh/1', name: 'Slack', url: 'https://hooks.example/slack', severity_filter: ['warning'], enabled: true,
    delivery_count: 1500, failure_count: 2500000, last_delivery: null };
const PAGER = { id: 'wh2', name: 'Pager', url: 'https://hooks.example/pager', enabled: false };

test('webhook, delivery-log and syslog strings from the server cannot add markup to the tab', async () => {
    const page = await notificationsTab({
        webhooks: [{ id: ATTR_MARKUP, name: MARKUP, url: MARKUP, severity_filter: [ATTR_MARKUP, 'critical'], enabled: true }],
        log: [{ timestamp: '2026-11-10T11:00:00Z', webhook_name: MARKUP, alert_id: MARKUP, severity: ATTR_MARKUP, success: false, error: MARKUP },
            { timestamp: '2026-11-10T11:01:00Z', webhook_id: MARKUP, success: true }],
        targets: [{ id: ATTR_MARKUP, host: MARKUP, port: MARKUP, protocol: MARKUP, facility: MARKUP, severity_filter: [ATTR_MARKUP], enabled: false }],
    });
    for (const id of ['admin-webhooks-tbody', 'admin-delivery-log-tbody', 'admin-syslog-tbody']) {
        assertInert(page.byId(id), id);
        // The markup stays in its own cell: no row gains or loses a column.
        const widths = page.byId(id).querySelectorAll('tr').map(tr => tr.children.length);
        assert.ok(widths.length > 0 && widths.every(width => width === widths[0]), id + ' rows keep one width: ' + widths);
    }
    assert.equal(page.byId('admin-webhooks-tbody').querySelector('[data-wh-test]').getAttribute('data-wh-test'), ATTR_MARKUP);
    assert.equal(page.byId('admin-syslog-tbody').querySelector('[data-sl-test]').getAttribute('data-sl-test'), ATTR_MARKUP);
});

test('the webhook list shows each endpoint\'s filter, state and delivery counts', async () => {
    const page = await notificationsTab({ webhooks: [SLACK, PAGER] });
    const [slack, pager] = page.byId('admin-webhooks-tbody').querySelectorAll('tr');
    assert.deepEqual(['Name', 'URL', 'Severity', 'Enabled', 'Sent', 'Fails', 'Last'].map(label => cell(slack, label).textContent.trim()),
        ['Slack', 'https://hooks.example/slack', page.context.severityIcon('warning').replace(/<[^>]*>/g, '') + 'warning', 'On', '1.5K', '2.5M', '--']);
    assert.deepEqual(['Severity', 'Enabled', 'Sent', 'Fails'].map(label => cell(pager, label).textContent.trim()), ['', 'Off', '0', '0']);
    assert.equal(slack.querySelector('[data-wh-toggle]').textContent, 'Disable');
    assert.equal(pager.querySelector('[data-wh-toggle]').textContent, 'Enable');
});

test('editing a webhook fills the form with its settings and saves them to that webhook only', async () => {
    let refuse = false;
    const page = await notificationsTab({
        webhooks: [SLACK, PAGER],
        routes: {
            'PUT /api/admin/webhooks/wh%2F1': () => (refuse ? reply(500) : reply(200, {})),
            'POST /api/admin/webhooks': () => reply(201, {}),
        },
    });
    const form = page.byId('admin-webhook-form'), url = page.byId('webhook-url-input'), name = page.byId('webhook-name-input');
    const severity = page.byId('webhook-severity-input');
    await page.click(page.byId('admin-webhooks-tbody').querySelector('[data-wh-edit="wh/1"]'));
    assert.deepEqual([form.style.display, url.value, name.value, chosen(severity)], ['', SLACK.url, 'Slack', ['warning']]);

    name.value = 'Slack #alerts';
    await page.click(page.byId('webhook-save-btn'));
    const [update] = page.writes();
    assert.deepEqual(call(update), ['PUT', '/api/admin/webhooks/wh%2F1', { url: SLACK.url, name: 'Slack #alerts', severity_filter: ['warning'] }]);
    assertCookieWrite(update);
    assert.equal(form.style.display, 'none');
    assert.deepEqual(lastToast(page), { text: 'Webhook updated', type: 'success', markup: 0 });

    // A webhook with no stored name, URL or filter opens with empty fields.
    page.server.webhooks = [{ id: 'bare', enabled: true }];
    await page.tab('notifications');
    await page.click(page.byId('admin-webhooks-tbody').querySelector('[data-wh-edit="bare"]'));
    assert.deepEqual([url.value, name.value, chosen(severity)], ['', '', []]);

    page.server.webhooks = [SLACK];
    await page.tab('notifications');
    await page.click(page.byId('admin-webhooks-tbody').querySelector('[data-wh-edit="wh/1"]'));
    refuse = true;
    await page.click(page.byId('webhook-save-btn'));
    assert.deepEqual(lastToast(page), { text: 'Failed to update webhook: HTTP 500', type: 'error', markup: 0 });
    assert.equal(form.style.display, '', 'a refused update keeps the form open');

    // Cancel ends the edit: the next save creates a new webhook.
    await page.click(page.byId('webhook-cancel-btn'));
    assert.equal(form.style.display, 'none');
    await page.click(page.byId('admin-add-webhook-btn'));
    url.value = 'https://hooks.example/new';
    await page.click(page.byId('webhook-save-btn'));
    assert.deepEqual(page.writes().map(r => r.method + ' ' + r.url).slice(-1), ['POST /api/admin/webhooks']);
});

test('toggling a webhook sends the opposite of its shown state', async () => {
    const page = await notificationsTab({
        webhooks: [SLACK, PAGER],
        routes: { 'PUT /api/admin/webhooks/wh%2F1': () => reply(200, {}), 'PUT /api/admin/webhooks/wh2': () => reply(200, {}) },
    });
    const before = gets(page, '/api/admin/webhooks');
    await page.click(page.byId('admin-webhooks-tbody').querySelector('[data-wh-toggle="wh/1"]'));
    await page.click(page.byId('admin-webhooks-tbody').querySelector('[data-wh-toggle="wh2"]'));
    assert.deepEqual(page.writes().map(call), [
        ['PUT', '/api/admin/webhooks/wh%2F1', { enabled: false }],
        ['PUT', '/api/admin/webhooks/wh2', { enabled: true }],
    ]);
    assert.equal(gets(page, '/api/admin/webhooks'), before + 2, 'each change reloads the list');
});

test('testing a webhook shows the delivery outcome on its button, then offers the test again', async () => {
    let outcome = () => reply(200, { status: 'delivered' });
    const page = await notificationsTab({ webhooks: [SLACK], routes: { 'POST /api/admin/webhooks/wh%2F1/test': () => outcome() } });
    const testButton = () => page.byId('admin-webhooks-tbody').querySelector('[data-wh-test="wh/1"]');
    let button = testButton();
    button.click();
    assert.deepEqual([button.textContent, button.disabled], ['...', true]);
    await page.advance(0);
    assert.equal(button.textContent, 'OK');
    await page.advance(2000);
    assert.deepEqual([button.textContent, button.disabled], ['Test', false]);

    for (const [answer, label] of [[() => reply(200, { status: 'failed', error: 'timeout' }), 'Fail'], [() => reply(502), 'Err']]) {
        outcome = answer;
        button = testButton();
        await page.click(button);
        assert.equal(button.textContent, label);
        await page.advance(1999);
        assert.equal(button.textContent, label);
        await page.advance(1);
        assert.deepEqual([button.textContent, button.disabled], ['Test', false]);
    }
    assert.deepEqual(page.writes().map(r => r.method + ' ' + r.url), Array(3).fill('POST /api/admin/webhooks/wh%2F1/test'));
});

test('deleting a webhook needs confirmation; a refusal says why', async () => {
    let refuse = true;
    const page = await notificationsTab({
        webhooks: [SLACK],
        routes: { 'DELETE /api/admin/webhooks/wh%2F1': () => (refuse ? reply(409, { detail: 'webhook is in use' }) : reply(204)) },
    });
    const remove = () => page.click(page.byId('admin-webhooks-tbody').querySelector('[data-wh-delete="wh/1"]'));
    await remove();
    assert.match(page.modal().textContent, /Any pending deliveries will be dropped\./);
    await page.click(page.button('Cancel'));
    assert.deepEqual(page.writes(), []);
    await remove();
    await page.click(page.button('Delete'));
    assert.deepEqual(lastToast(page), { text: 'Failed to delete webhook: webhook is in use', type: 'error', markup: 0 });
    refuse = false;
    page.server.webhooks = [];
    await remove();
    await page.click(page.button('Delete'));
    assert.deepEqual(lastToast(page), { text: 'Webhook deleted', type: 'success', markup: 0 });
    assert.deepEqual(page.writes().map(call), Array(2).fill(['DELETE', '/api/admin/webhooks/wh%2F1', undefined]));
    assert.equal(page.byId('admin-webhooks-tbody').innerHTML, '');
    assert.equal(page.byId('admin-webhooks-empty').style.display, '');
});

test('the delivery log lists the newest delivery first, with each attempt\'s outcome', async () => {
    const log = [
        { timestamp: '2026-11-10T11:00:00Z', webhook_id: 'wh2', alert_id: null, severity: null, success: false, error: 'connect timeout' },
        { timestamp: '2026-11-10T11:05:00Z', webhook_name: 'Slack', webhook_id: 'wh/1', alert_id: 'alert_9', severity: 'critical', success: true },
    ];
    const page = await notificationsTab({ log });
    assert.equal(page.byId('admin-delivery-empty').style.display, 'none');
    assert.equal(page.byId('admin-delivery-log-table').style.display, '');
    const rows = page.byId('admin-delivery-log-tbody').querySelectorAll('tr');
    const read = row => ['Webhook', 'Alert', 'Status', 'Error'].map(label => cell(row, label).textContent);
    assert.deepEqual(rows.map(read), [['Slack', 'alert_9', 'delivered', '--'], ['wh2', '--', 'failed', 'connect timeout']]);
    assert.match(cell(rows[0], 'Severity').textContent, /critical$/);
    assert.equal(cell(rows[1], 'Severity').textContent, '--');

    page.server.log = [];
    await page.tab('notifications');
    assert.equal(page.byId('admin-delivery-log-tbody').innerHTML, '');
    assert.equal(page.byId('admin-delivery-empty').style.display, '');
    assert.equal(page.byId('admin-delivery-log-table').style.display, 'none');
});

/* ------------------------------------------------------------------ */
/* Syslog forwarding                                                   */
/* ------------------------------------------------------------------ */

const field = (page, name) => page.byId('syslog-' + name + '-input');
const syslogForm = page => ({
    shown: page.byId('admin-syslog-form').style.display,
    edit: page.byId('syslog-edit-id').value,
    host: field(page, 'host').value, port: field(page, 'port').value, protocol: field(page, 'protocol').value,
    facility: field(page, 'facility').value, severity: chosen(field(page, 'severity')),
    classes: field(page, 'class').value, nodes: field(page, 'node').value,
    ca: field(page, 'ca').value, cert: field(page, 'cert').value, key: field(page, 'key').value,
    tls: page.byId('syslog-tls-fields').style.display,
});

test('adding a syslog target: the form opens with the defaults; host and port are checked before sending', async () => {
    let refuse = false;
    const page = await notificationsTab({
        routes: {
            'POST /api/admin/syslog': request => {
                if (refuse) return reply(400, { detail: 'TLS CA bundle not found' });
                page.server.targets.push({ id: 'sl_' + page.server.targets.length, enabled: true, ...request.body });
                return reply(201, {});
            },
        },
    });
    assert.equal(page.byId('admin-syslog-empty').style.display, '');
    assert.equal(page.byId('admin-syslog-table').style.display, 'none');
    for (const name of ['host', 'class', 'node', 'ca', 'cert', 'key']) field(page, name).value = 'left over';
    field(page, 'port').value = '1';
    field(page, 'protocol').value = 'tcp';
    page.byId('syslog-edit-id').value = 'old';
    choose(field(page, 'severity'), ['info']);
    await page.click(page.byId('admin-add-syslog-btn'));
    assert.deepEqual(syslogForm(page), {
        shown: '', edit: '', host: '', port: '514', protocol: 'udp', facility: 'local0', severity: ['critical', 'warning'],
        classes: '', nodes: '', ca: '', cert: '', key: '', tls: 'none',
    });
    assert.equal(page.doc.activeElement, field(page, 'host'));

    const save = () => page.click(page.byId('syslog-save-btn'));
    await save();
    assert.deepEqual(lastToast(page), { text: 'Host is required.', type: 'error', markup: 0 });
    field(page, 'host').value = ' logs.example ';
    for (const port of ['0', '65536', 'abc']) {
        field(page, 'port').value = port;
        await save();
        assert.deepEqual(lastToast(page), { text: 'Port must be 1-65535.', type: 'error', markup: 0 }, port);
        assert.equal(page.doc.activeElement, field(page, 'port'));
    }
    assert.deepEqual(page.writes(), [], 'nothing invalid is sent');

    field(page, 'port').value = '6514';
    await page.change(field(page, 'protocol'), 'tls');
    assert.equal(page.byId('syslog-tls-fields').style.display, '', 'TLS settings appear for TLS');
    field(page, 'facility').value = 'auth';
    choose(field(page, 'severity'), ['critical', 'warning', 'info']);
    field(page, 'class').value = ' wifi, ,bluetooth ';
    field(page, 'node').value = 'node-01';
    field(page, 'ca').value = ' /etc/ssl/ca.pem ';
    field(page, 'key').value = ' /etc/ssl/client.key ';
    await save();
    const [created] = page.writes();
    assert.deepEqual(call(created), ['POST', '/api/admin/syslog', {
        host: 'logs.example', port: 6514, protocol: 'tls', facility: 'auth', severity_filter: ['critical', 'warning', 'info'],
        signal_class_filter: ['wifi', 'bluetooth'], node_filter: ['node-01'],
        tls_ca_bundle: '/etc/ssl/ca.pem', tls_client_key: '/etc/ssl/client.key',
    }]);
    assertCookieWrite(created);
    assert.equal(page.byId('admin-syslog-form').style.display, 'none');
    assert.deepEqual(lastToast(page), { text: 'Syslog target created', type: 'success', markup: 0 });
    assert.equal(cell(page.byId('admin-syslog-tbody'), 'Host').textContent, 'logs.example', 'the list is reloaded');
    assert.equal(page.byId('admin-syslog-empty').style.display, 'none');

    // UDP sends no TLS paths, even ones left in the hidden fields; no severity chosen sends the default.
    await page.click(page.byId('admin-add-syslog-btn'));
    field(page, 'host').value = 'udp.example';
    await page.change(field(page, 'protocol'), 'tls');
    field(page, 'cert').value = '/etc/ssl/client.pem';
    await page.change(field(page, 'protocol'), 'udp');
    assert.equal(page.byId('syslog-tls-fields').style.display, 'none');
    choose(field(page, 'severity'), []);
    await save();
    assert.deepEqual(page.writes()[1].body, {
        host: 'udp.example', port: 514, protocol: 'udp', facility: 'local0', severity_filter: ['critical', 'warning'],
        signal_class_filter: [], node_filter: [],
    });

    refuse = true;
    await page.click(page.byId('admin-add-syslog-btn'));
    field(page, 'host').value = 'tls.example';
    await page.change(field(page, 'protocol'), 'tls');
    await save();
    assert.deepEqual(page.writes()[2].body.protocol, 'tls');
    assert.equal('tls_client_cert' in page.writes()[2].body, false, 'empty TLS fields are not sent');
    assert.deepEqual(lastToast(page), { text: 'Failed to create syslog target: TLS CA bundle not found', type: 'error', markup: 0 });
    assert.equal(page.byId('admin-syslog-form').style.display, '');
    await page.click(page.byId('syslog-cancel-btn'));
    assert.equal(page.byId('admin-syslog-form').style.display, 'none');
});

const TLS_TARGET = {
    id: 'sl/1', host: 'logs.example', port: 6514, protocol: 'tls', facility: 'local3', severity_filter: ['critical'],
    signal_class_filter: ['wifi', 'zigbee'], node_filter: ['node-01'], tls_ca_bundle: '/ca.pem', tls_client_cert: '/client.pem',
    tls_client_key: '/client.key', enabled: true, delivery_count: 2048, failure_count: 3, last_delivery: '2026-11-10T11:00:00Z',
};
const PLAIN_TARGET = { id: 'sl2', host: '10.0.0.9', enabled: false };

test('the syslog list shows each target\'s transport, filter, state and counts', async () => {
    const page = await notificationsTab({ targets: [TLS_TARGET, PLAIN_TARGET] });
    const [tls, plain] = page.byId('admin-syslog-tbody').querySelectorAll('tr');
    const read = row => ['Host', 'Port', 'Protocol', 'Facility', 'Enabled', 'Sent', 'Fails'].map(label => cell(row, label).textContent);
    assert.deepEqual(read(tls), ['logs.example', '6514', 'TLS', 'local3', 'On', '2.0K', '3']);
    assert.deepEqual(read(plain), ['10.0.0.9', '', 'UDP', 'local0', 'Off', '0', '0']);
    assert.match(cell(tls, 'Severity').textContent.trim(), /critical$/);
    assert.equal(cell(plain, 'Severity').textContent, '');
    assert.equal(cell(tls, 'Last').textContent, page.context.fmtTime(TLS_TARGET.last_delivery));
    assert.equal(cell(plain, 'Last').textContent, '--');
    assert.deepEqual([tls, plain].map(row => row.querySelector('[data-sl-toggle]').textContent), ['Disable', 'Enable']);
});

test('editing a syslog target fills every field, TLS included, and saves to that target', async () => {
    let refuse = false;
    const page = await notificationsTab({
        targets: [TLS_TARGET, PLAIN_TARGET],
        routes: {
            'PUT /api/admin/syslog/sl%2F1': () => (refuse ? reply(503) : reply(200, {})),
            'PUT /api/admin/syslog/sl2': () => reply(200, {}),
        },
    });
    const edit = id => page.click(page.byId('admin-syslog-tbody').querySelector('[data-sl-edit="' + id + '"]'));
    await edit('sl/1');
    assert.deepEqual(syslogForm(page), {
        shown: '', edit: 'sl/1', host: 'logs.example', port: '6514', protocol: 'tls', facility: 'local3', severity: ['critical'],
        classes: 'wifi, zigbee', nodes: 'node-01', ca: '/ca.pem', cert: '/client.pem', key: '/client.key', tls: '',
    });
    await page.click(page.byId('syslog-save-btn'));
    const [update] = page.writes();
    assert.deepEqual(call(update), ['PUT', '/api/admin/syslog/sl%2F1', {
        host: 'logs.example', port: 6514, protocol: 'tls', facility: 'local3', severity_filter: ['critical'],
        signal_class_filter: ['wifi', 'zigbee'], node_filter: ['node-01'],
        tls_ca_bundle: '/ca.pem', tls_client_cert: '/client.pem', tls_client_key: '/client.key',
    }]);
    assertCookieWrite(update);
    assert.equal(page.byId('admin-syslog-form').style.display, 'none');
    assert.deepEqual(lastToast(page), { text: 'Syslog target updated', type: 'success', markup: 0 });

    // A target stored without a port, transport or filters opens with the defaults.
    await edit('sl2');
    assert.deepEqual(syslogForm(page), {
        shown: '', edit: 'sl2', host: '10.0.0.9', port: '514', protocol: 'udp', facility: 'local0', severity: [],
        classes: '', nodes: '', ca: '', cert: '', key: '', tls: 'none',
    });
    await page.click(page.byId('syslog-save-btn'));
    assert.deepEqual(page.writes()[1].body, {
        host: '10.0.0.9', port: 514, protocol: 'udp', facility: 'local0', severity_filter: ['critical', 'warning'],
        signal_class_filter: [], node_filter: [],
    });

    await edit('sl/1');
    refuse = true;
    await page.click(page.byId('syslog-save-btn'));
    assert.deepEqual(lastToast(page), { text: 'Failed to update syslog target: HTTP 503', type: 'error', markup: 0 });
    assert.equal(page.byId('admin-syslog-form').style.display, '');
});

test('toggling a syslog target sends the opposite of its shown state and reloads the list', async () => {
    const page = await notificationsTab({
        targets: [TLS_TARGET, PLAIN_TARGET],
        routes: { 'PUT /api/admin/syslog/sl%2F1': () => reply(200, {}), 'PUT /api/admin/syslog/sl2': () => reply(500) },
    });
    const before = gets(page, '/api/admin/syslog');
    await page.click(page.byId('admin-syslog-tbody').querySelector('[data-sl-toggle="sl/1"]'));
    await page.click(page.byId('admin-syslog-tbody').querySelector('[data-sl-toggle="sl2"]'));
    assert.deepEqual(page.writes().map(call), [
        ['PUT', '/api/admin/syslog/sl%2F1', { enabled: false }],
        ['PUT', '/api/admin/syslog/sl2', { enabled: true }],
    ]);
    assert.equal(gets(page, '/api/admin/syslog'), before + 1, 'only the accepted change reloads the list');
});

test('testing a syslog target shows the outcome on its button, then offers the test again', async () => {
    let outcome = () => reply(200, { status: 'delivered' });
    const page = await notificationsTab({ targets: [TLS_TARGET], routes: { 'POST /api/admin/syslog/sl%2F1/test': () => outcome() } });
    const testButton = () => page.byId('admin-syslog-tbody').querySelector('[data-sl-test="sl/1"]');
    for (const [answer, label] of [[() => reply(200, { status: 'delivered' }), 'OK'], [() => reply(200, { status: 'refused' }), 'Fail'],
        [() => reply(500, { detail: 'boom' }), 'Err']]) {
        outcome = answer;
        const button = testButton();
        button.click();
        assert.deepEqual([button.textContent, button.disabled], ['...', true]);
        await page.advance(0);
        assert.equal(button.textContent, label);
        await page.advance(2000);
        assert.deepEqual([button.textContent, button.disabled], ['Test', false]);
    }
    assert.equal(page.writes().length, 3);
});

test('deleting a syslog target needs confirmation; a refusal says why', async () => {
    let refuse = true;
    const page = await notificationsTab({
        targets: [TLS_TARGET],
        routes: { 'DELETE /api/admin/syslog/sl%2F1': () => (refuse ? reply(404, { detail: 'no such target' }) : reply(204)) },
    });
    const remove = () => page.click(page.byId('admin-syslog-tbody').querySelector('[data-sl-delete="sl/1"]'));
    await remove();
    assert.match(page.modal().textContent, /Forwarding to it will stop immediately\./);
    await page.key('Escape');
    assert.deepEqual(page.writes(), []);
    await remove();
    await page.click(page.button('Delete'));
    assert.deepEqual(lastToast(page), { text: 'Failed to delete syslog target: no such target', type: 'error', markup: 0 });
    refuse = false;
    page.server.targets = [];
    await remove();
    await page.click(page.button('Delete'));
    assert.deepEqual(lastToast(page), { text: 'Syslog target deleted', type: 'success', markup: 0 });
    assert.deepEqual(page.writes().map(call), Array(2).fill(['DELETE', '/api/admin/syslog/sl%2F1', undefined]));
    assert.equal(page.byId('admin-syslog-empty').style.display, '');
    assert.equal(page.byId('admin-syslog-table').style.display, 'none');
});

test('a load or change refused without an explanation reports its HTTP status', async () => {
    let list = () => reply(200, { webhooks: [SLACK], delivery_log: [] });
    const page = await notificationsTab({
        targets: [TLS_TARGET],
        routes: {
            'GET /api/admin/webhooks': () => list(),
            'POST /api/admin/webhooks': () => reply(500),
            'DELETE /api/admin/webhooks/wh%2F1': () => reply(500),
            'POST /api/admin/syslog': () => reply(500),
            'DELETE /api/admin/syslog/sl%2F1': () => reply(500),
        },
    });
    await page.click(page.byId('admin-add-webhook-btn'));
    page.byId('webhook-url-input').value = 'https://hooks.example/x';
    await page.click(page.byId('webhook-save-btn'));
    assert.deepEqual(lastToast(page), { text: 'Failed to create webhook: HTTP 500', type: 'error', markup: 0 });
    await page.click(page.byId('admin-webhooks-tbody').querySelector('[data-wh-delete="wh/1"]'));
    await page.click(page.button('Delete'));
    assert.deepEqual(lastToast(page), { text: 'Failed to delete webhook: HTTP 500', type: 'error', markup: 0 });
    await page.click(page.byId('admin-add-syslog-btn'));
    field(page, 'host').value = 'logs.example';
    await page.click(page.byId('syslog-save-btn'));
    assert.deepEqual(lastToast(page), { text: 'Failed to create syslog target: HTTP 500', type: 'error', markup: 0 });
    await page.click(page.byId('admin-syslog-tbody').querySelector('[data-sl-delete="sl/1"]'));
    await page.click(page.button('Delete'));
    assert.deepEqual(lastToast(page), { text: 'Failed to delete syslog target: HTTP 500', type: 'error', markup: 0 });

    for (const [answer, text] of [[() => reply(503, { detail: 'notification store offline' }), 'Failed to load webhooks: notification store offline'],
        [() => reply(500), 'Failed to load webhooks: HTTP 500']]) {
        list = answer;
        await page.tab('notifications');
        assert.deepEqual(lastToast(page), { text, type: 'error', markup: 0 });
        assert.equal(page.byId('admin-webhooks-tbody').querySelectorAll('tr').length, 1, 'a failed reload keeps the list shown');
    }
});
