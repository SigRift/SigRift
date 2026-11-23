/* The admin console's Database, Logs and System tabs (admin.js): table
 * statistics, job history, maintenance results, backups, the log viewer and
 * the runtime metrics, driven through the controls of templates/admin.html
 * in the admin_dom.cjs stub DOM. */
const assert = require('node:assert/strict');
const test = require('node:test');
const { adminPage, noUnexpectedConsoleErrors, reply, assertCookieWrite, call } = require('./admin_dom.cjs');

test.afterEach(noUnexpectedConsoleErrors);

const lastToast = page => page.toasts().at(-1);
const gets = (page, prefix) => page.requests.filter(r => r.method === 'GET' && r.url.startsWith(prefix)).map(r => r.url);
const rowsOf = (el, selector = 'tbody tr') => el.querySelectorAll(selector).map(tr => tr.children.map(td => td.textContent));

/* The database tab with a server answering stats, jobs and backups. The
 * bootstrap's /api/admin/stats (no period) authenticates. */
async function databaseTab({ stats = {}, jobs = { jobs: [] }, backups = { backups: [] }, routes = {}, storage, cookie } = {}) {
    const server = { stats, jobs, backups, opened: false };
    const page = await adminPage({
        storage, cookie,
        routes: {
            'GET /api/admin/stats': () => reply(200, server.opened ? server.stats : {}),
            'GET /api/admin/jobs': () => (typeof server.jobs === 'function' ? server.jobs() : reply(200, server.jobs)),
            'GET /api/admin/backups': () => (typeof server.backups === 'function' ? server.backups() : reply(200, server.backups)),
            ...routes,
        },
    });
    page.server = server;
    server.opened = true;
    await page.tab('database');
    return page;
}

/* ------------------------------------------------------------------ */
/* Table statistics                                                    */
/* ------------------------------------------------------------------ */

const STATS = {
    db_path: '/var/lib/sigrift/bridge.db', db_size_bytes: 2147483648, wal_size_bytes: 1048576,
    table_stats: [
        { name: 'detections', rows: 1500000, size_bytes: 2147483648, rows_1h: 1200, rows_24h: 25000, rows_period: 25000,
            oldest: '2026-10-01T00:00:00Z', newest: '2026-11-10T11:59:00Z' },
        { name: 'audit_log', rows: 999, size_bytes: 5242880, rows_1h: null, rows_24h: 0, rows_period: 0 },
        { name: 'custom_table', rows: 10, size_bytes: 2048 },
        { name: 'sessions', size_bytes: 512 },
    ],
};

test('table statistics: labelled tables with sizes, recent rows and growth over the chosen period', async () => {
    const page = await databaseTab({ stats: STATS });
    assert.deepEqual(gets(page, '/api/admin/stats?'), ['/api/admin/stats?period_hours=24'], 'the page opens with the 24 h growth column');
    const el = page.byId('system-db-stats');
    assert.deepEqual(el.querySelectorAll('thead th').map(th => th.textContent), ['Table', 'Rows', 'Size', '1h', '24h', '24h', 'Oldest', 'Newest']);
    const time = page.context.fmtTime;
    assert.deepEqual(rowsOf(el), [
        ['RF Detectionsdetections', '1.5M', '2.0 GB', '1.2K', '25.0K', '+25.0K', time(STATS.table_stats[0].oldest), time(STATS.table_stats[0].newest)],
        ['Audit Logaudit_log', '999', '5.0 MB', '--', '0', '0', '--', '--'],
        ['custom_tablecustom_table', '10', '2.0 KB', '--', '--', '--', '--', '--'],
        ['Sessionssessions', '--', '512 B', '--', '--', '--', '--', '--'],
    ]);
    const growth = el.querySelectorAll('tbody tr').map(tr => tr.children[5].style.color);
    assert.deepEqual(growth, ['var(--accent-green)', '', '', ''], 'only actual growth is highlighted');
    assert.equal(el.querySelector('p').textContent, 'Total rows: 1.5M | DB: /var/lib/sigrift/bridge.db (2.0 GB) | WAL: 1.0 MB');

    for (const [period, label] of [['168', '7d'], ['48', '48h'], ['1', '1h']]) {
        await page.change(page.byId('db-stats-period'), period);
        assert.equal(gets(page, '/api/admin/stats?').at(-1), '/api/admin/stats?period_hours=' + period);
        assert.equal(el.querySelectorAll('thead th')[5].textContent, label);
    }
    await page.change(page.byId('db-stats-period'), '0');
    assert.equal(page.requests.at(-1).url, '/api/admin/stats', 'no growth column asks for no period');
    assert.deepEqual(el.querySelectorAll('thead th').map(th => th.textContent), ['Table', 'Rows', 'Size', '1h', '24h', 'Oldest', 'Newest']);
});

test('table statistics from an older server: the plain row counts, and zero totals', async () => {
    const page = await databaseTab({ stats: { tables: { detections: 5, audit_log: 2 } } });
    const el = page.byId('system-db-stats');
    assert.deepEqual(el.querySelectorAll('thead th').map(th => th.textContent), ['Table', 'Rows']);
    assert.deepEqual(rowsOf(el), [['detections', '5'], ['audit_log', '2']]);
    assert.equal(el.querySelector('p').textContent, 'Total rows: 0 | DB:  (0 B) | WAL: 0 B');
});

/* ------------------------------------------------------------------ */
/* Job history                                                         */
/* ------------------------------------------------------------------ */

const JOBS = {
    next_scheduled_cleanup: '2026-11-11T03:00:00Z',
    jobs: [
        { task: 'purge_old_data', trigger: 'scheduled', status: 'completed', duration_s: 4.2,
            result: { deleted: { detections: 1200, wifi_metadata: 0, audit_log: 5 }, aggregated: 2000000, aggregated_wifi_hourly: 3,
                dismissed: 7, vacuumed: true, reclaimed_bytes: 3145728 } },
        { task: 'vacuum', trigger: 'manual', status: 'failed', error: 'database is locked', operator: 'adminkey_123456789' },
        { task: 'scheduled_cleanup', trigger: 'scheduled', status: 'completed', operator: 'system',
            result: { deleted: 12, reclaimed_bytes: 2048, deleted_detections: 3, deleted_wifi_metadata: 4, deleted_rf_anomalies: 5,
                deleted_wifi_anomalies: 6, deleted_wifi_hourly: 7 } },
        { task: 'optimize', status: 'completed', result: { deleted: 0, reclaimed_bytes: 100 } },
        { task: 'aggregate_wifi', status: 'completed', result: {} },
        { task: 'purge_iq_captures', status: 'completed', note: 'recorded in the audit log' },
        { task: 'reeval_dismiss_rf', status: 'running', duration_s: null },
        { task: 'wal_checkpoint', status: 'queued' },
    ],
};

test('job history: each job\'s trigger, outcome and what it changed', async () => {
    const page = await databaseTab({ jobs: JOBS });
    const el = page.byId('db-jobs');
    assert.equal(el.firstChild.textContent, 'Next scheduled cleanup: ' + page.context.fmtTime(JOBS.next_scheduled_cleanup));
    const rows = rowsOf(el).map(([task, trigger, status, , duration, details]) => [task, trigger, status, duration, details]);
    assert.deepEqual(rows, [
        ['purge_old_data', 'scheduled', 'completed', '4.2s',
            'detections: 1.2K, audit_log: 5, 2.0M aggregated, wifi: 3 agg, 7 dismissed, vacuumed, reclaimed 3.0MB'],
        ['vacuum', 'manual', 'failed', '--', 'database is locked [adminkey]'],
        ['scheduled_cleanup', 'scheduled', 'completed', '--', '12 deleted, reclaimed 2.0KB, det: 3, wifi: 4, rf_anom: 5, wifi_anom: 6, hourly: 7'],
        ['optimize', 'manual', 'completed', '--', 'reclaimed 100B'],
        ['aggregate_wifi', 'manual', 'completed', '--', 'ok'],
        ['purge_iq_captures', 'manual', 'completed', '--', 'recorded in the audit log'],
        ['reeval_dismiss_rf', 'manual', 'running', '--', 'in progress...'],
        ['wal_checkpoint', 'manual', 'queued', '--', ''],
    ]);
    const statusColors = el.querySelectorAll('tbody tr').map(tr => tr.children[2].style.color);
    assert.deepEqual(statusColors, ['var(--accent-green)', 'var(--accent-red)', 'var(--accent-green)', 'var(--accent-green)',
        'var(--accent-green)', 'var(--accent-green)', 'var(--accent-cyan)', '']);
});

test('job history: none yet, a refresh, and a failed load', async () => {
    const page = await databaseTab({ jobs: { jobs: [] } });
    assert.equal(page.byId('db-jobs').innerHTML, '<p class="empty-state">No recent jobs</p>');
    page.server.jobs = { next_scheduled_cleanup: '2026-11-11T03:00:00Z' };
    await page.click(page.byId('jobs-refresh-btn'));
    assert.equal(page.byId('db-jobs').textContent, 'Next scheduled cleanup: ' + page.context.fmtTime('2026-11-11T03:00:00Z') + 'No recent jobs');
    page.server.jobs = () => reply(500);
    await page.click(page.byId('jobs-refresh-btn'));
    assert.equal(page.byId('db-jobs').textContent, 'Failed to load jobs');
});

/* ------------------------------------------------------------------ */
/* Maintenance results                                                 */
/* ------------------------------------------------------------------ */

async function runTask(page, task) {
    await page.click(page.doc.querySelector('.maint-task-btn[data-task="' + task + '"]'));
    await page.click(page.button('Run'));
    return page.byId('maint-result');
}

/* A result as the browser lays it out: one string per line, split at each <br>. */
function lines(el) {
    const out = [''];
    (function walk(node) {
        for (const child of node.childNodes) {
            if (child.nodeType === 3) out[out.length - 1] += child.textContent;
            else if (child.localName === 'br') out.push('');
            else if (child.nodeType === 1) walk(child);
        }
    })(el);
    return out.filter(line => line !== '');
}

test('each maintenance result reports what the task did, then statistics and jobs reload', async () => {
    let answer;
    const page = await databaseTab({ routes: { 'POST /api/admin/maintenance': () => reply(200, answer) } });
    const reloads = () => [gets(page, '/api/admin/stats?').length, gets(page, '/api/admin/jobs').length];
    const before = reloads();
    for (const [task, result, expected] of [
        ['wal_checkpoint', { wal_pages: 12, checkpointed: 12, db_size_bytes: 20480 }, ['WAL Checkpoint completed. DB size: 20.0 KB WAL pages: 12, checkpointed: 12']],
        ['aggregate_detections', { aggregated: 40, aggregated_wifi_hourly: 2 },
            ['Detection Hourly Aggregation completed. 40 hourly buckets aggregated.', 'WiFi hourly: 2 buckets aggregated.']],
        ['reeval_dismiss_rf', { processed: 10, dismissed: 4, still_active: 6 },
            ['Re-evaluate & Dismiss Resolved RF completed.', 'Processed: 10, dismissed: 4, still active: 6']],
        ['reeval_dismiss_wifi', { processed: 3 }, ['Re-evaluate & Dismiss Resolved WiFi completed.', 'Processed: 3']],
        ['aggregate_wifi', {}, ['WiFi Hourly Summarization completed.']],
    ]) {
        answer = result;
        const el = await runTask(page, task);
        assert.equal(el.style.display, '');
        assert.deepEqual(lines(el), expected, task);
    }
    // A task that vacuums ends with a line saying what VACUUM reclaimed and the size left.
    for (const [task, result, first, facts] of [
        ['vacuum', { vacuumed: true, reclaimed_bytes: 5242880, db_size_bytes: 1536 }, 'VACUUM (reclaim disk) completed.', ['Reclaimed: 5.0 MB', 'DB size: 1.5 KB']],
        ['optimize', { vacuumed: true, reclaimed_bytes: 512, db_size_bytes: 3145728 }, 'Optimize (ANALYZE) completed.', ['Reclaimed: 512 B', 'DB size: 3.0 MB']],
        ['dismiss_all_rf', { vacuumed: true, reclaimed_bytes: 2048 }, 'Dismiss All RF Anomalies completed.', ['Reclaimed: 2.0 KB']],
        ['dismiss_all_wifi', { vacuumed: true, db_size_bytes: 100, deleted: 9 }, 'Dismiss All WiFi Anomalies completed. 9 rows/files removed.', ['DB size: 100 B']],
    ]) {
        answer = result;
        const shown = lines(await runTask(page, task));
        assert.equal(shown.length, 2, task + ': ' + shown);
        assert.ok(shown[0].startsWith(first), task + ': ' + shown[0]);
        assert.ok(shown[1].startsWith('VACUUM completed.'), task + ': ' + shown[1]);
        for (const fact of facts) assert.ok(shown[1].includes(fact), task + ': ' + fact + ' in ' + shown[1]);
        if (!('reclaimed_bytes' in result)) assert.ok(!shown[1].includes('Reclaimed'), task + ': nothing reclaimed is reported');
    }
    const [stats, jobs] = reloads();
    assert.deepEqual([stats - before[0], jobs - before[1]], [9, 9], 'every task reloads the statistics and job history');
    assert.deepEqual(page.writes().map(r => r.body.task), ['wal_checkpoint', 'aggregate_detections', 'reeval_dismiss_rf',
        'reeval_dismiss_wifi', 'aggregate_wifi', 'vacuum', 'optimize', 'dismiss_all_rf', 'dismiss_all_wifi']);
});

test('a task that vacuums states the database size once', async () => {
    const page = await databaseTab({ routes: { 'POST /api/admin/maintenance': () => reply(200, { vacuumed: true, reclaimed_bytes: 512, db_size_bytes: 3145728 }) } });
    const el = await runTask(page, 'optimize');
    assert.equal(el.textContent.split('DB size').length - 1, 1, el.textContent);
});

test('a task that does not vacuum states the database size once, in the same units as a vacuum', async () => {
    const page = await databaseTab({ routes: { 'POST /api/admin/maintenance': () => reply(200, { wal_pages: 0, checkpointed: 0, db_size_bytes: 3145728 }) } });
    const el = await runTask(page, 'wal_checkpoint');
    assert.deepEqual(lines(el), ['WAL Checkpoint completed. DB size: 3.0 MB WAL pages: 0, checkpointed: 0']);
});

test('maintenance sizes switch unit at exactly 1 KB and 1 MB', async () => {
    for (const [bytes, shown] of [[1023, '1023 B'], [1024, '1.0 KB'], [1048575, '1024.0 KB'], [1048576, '1.0 MB']]) {
        const page = await databaseTab({ routes: { 'POST /api/admin/maintenance': () => reply(200, { wal_pages: 0, checkpointed: 0, db_size_bytes: bytes }) } });
        const el = await runTask(page, 'wal_checkpoint');
        assert.deepEqual(lines(el), ['WAL Checkpoint completed. DB size: ' + shown + ' WAL pages: 0, checkpointed: 0'], String(bytes));
    }
});

test('a one-day retention purge says "1 day"; Escape leaves the purge unrun', async () => {
    const page = await databaseTab({ routes: { 'POST /api/admin/maintenance': () => reply(200, { deleted: 42 }) } });
    await page.input(page.byId('maint-retention'), '1');
    const purge = page.doc.querySelector('.maint-task-btn[data-task="purge_detections"]');
    await page.click(purge);
    assert.match(page.modal().textContent, /Retention window: 1 day\. Rows older/);
    await page.key('Escape');
    assert.equal(page.modal(), null);
    assert.deepEqual(page.writes(), []);
    await page.click(purge);
    await page.input(page.modal().querySelector('#maint-confirm-input'), 'detections');
    await page.click(page.button('Delete'));
    assert.deepEqual(call(page.writes()[0]), ['POST', '/api/admin/maintenance', { task: 'purge_detections', retention_days: 1 }]);
    assert.equal(page.byId('maint-result').textContent, 'Purge Detections completed. 42 rows/files removed.');
});

/* ------------------------------------------------------------------ */
/* Backups                                                             */
/* ------------------------------------------------------------------ */

const BACKUPS = { backups: [
    { name: 'bridge-2026-11-10.db', size_bytes: 3145728, created: '2026-11-10T03:00:00Z' },
    { name: 'small.db', size_bytes: 2048, created: null },
    { name: 'empty.db' },
] };

test('the backup list shows each file\'s size and date; empty and failed lists say so', async () => {
    const page = await databaseTab({ backups: BACKUPS });
    const list = page.byId('backup-list');
    const items = () => list.querySelectorAll('.backup-item').map(item => item.children.map(child => child.textContent));
    assert.deepEqual(items(), [
        ['bridge-2026-11-10.db', '3.0 MB', page.context.fmtTime('2026-11-10T03:00:00Z'), 'Download'],
        ['small.db', '2.0 KB', '--', 'Download'],
        ['empty.db', '0 B', '--', 'Download'],
    ]);
    page.server.backups = { backups: [] };
    await page.click(page.byId('backup-refresh-btn'));
    assert.equal(list.textContent, 'No backups');
    page.server.backups = () => reply(503);
    await page.click(page.byId('backup-refresh-btn'));
    assert.equal(list.textContent, 'Failed to load backups');
});

test('creating a backup locks its button while it runs, reports the file, and lists it', async () => {
    let refuse = false;
    const page = await databaseTab({
        routes: {
            'POST /api/admin/backup': () => {
                if (refuse) return reply(507, { detail: 'disk full' });
                page.server.backups = { backups: [{ name: 'bridge-new.db', size_bytes: 10240 }] };
                return reply(200, { backup_file: 'bridge-new.db', size_bytes: 10240 });
            },
        },
    });
    const button = page.byId('backup-create-btn'), result = page.byId('backup-result');
    button.click();
    assert.deepEqual([button.disabled, button.textContent], [true, 'Creating...']);
    await page.advance(0);
    assert.deepEqual([button.disabled, button.textContent], [false, 'Create Backup']);
    assert.deepEqual(call(page.writes()[0]), ['POST', '/api/admin/backup', undefined]);
    assertCookieWrite(page.writes()[0], { json: false });
    assert.equal(result.style.display, '');
    assert.equal(result.textContent, 'Backup created! bridge-new.db (10.0 KB)');
    assert.equal(page.byId('backup-list').querySelector('.backup-name').textContent, 'bridge-new.db');

    refuse = true;
    await page.click(button);
    assert.equal(result.textContent, 'Failed: disk full');
    assert.deepEqual([button.disabled, button.textContent], [false, 'Create Backup']);
});

async function download(storage, cookie, routes = {}) {
    const page = await databaseTab({
        backups: BACKUPS, storage, cookie,
        routes: { 'GET /api/admin/backups/bridge-2026-11-10.db': () => new Response('SQLite format 3', { status: 200 }), ...routes },
    });
    const clicked = [];
    page.doc.body.addEventListener('click', event => { if (event.target.localName === 'a') clicked.push([event.target.getAttribute('download'), event.target.getAttribute('href')]); });
    await page.click(page.byId('backup-list').querySelector('[data-dl-backup="bridge-2026-11-10.db"]'));
    await page.advance(0);
    const request = page.requests.find(r => r.url.startsWith('/api/admin/backups/'));
    return { page, clicked, request };
}

test('downloading a backup fetches it with the page\'s credentials and saves it under its name', async () => {
    const cookieMode = await download();
    assert.equal(cookieMode.request.credentials, 'same-origin');
    assert.equal(cookieMode.request.headers['X-API-Key'], undefined);
    assert.equal(cookieMode.request.headers['X-Session-Token'], undefined);
    assert.deepEqual(cookieMode.clicked, [['bridge-2026-11-10.db', 'blob:admin/1']]);
    assert.equal(await cookieMode.page.blobs[0].text(), 'SQLite format 3');
    assert.equal(cookieMode.page.doc.body.querySelector('a[download]'), null, 'the temporary link is removed');

    const keyMode = await download({ bridge_admin_key: 'adm', bridge_session_token: 'tok' }, '');
    assert.equal(keyMode.request.headers['X-API-Key'], 'adm');
    assert.equal(keyMode.request.headers['X-Session-Token'], undefined);
    const tokenMode = await download({ bridge_session_token: 'tok' }, '');
    assert.equal(tokenMode.request.headers['X-Session-Token'], 'tok');
    assert.equal(tokenMode.request.headers['X-API-Key'], undefined);
});

test('a failed backup download says why and saves nothing', async () => {
    const { page, clicked } = await download(undefined, undefined, { 'GET /api/admin/backups/bridge-2026-11-10.db': () => reply(404) });
    assert.deepEqual(clicked, []);
    assert.deepEqual(page.blobs, []);
    assert.deepEqual(lastToast(page), { text: 'Download failed: HTTP 404', type: 'error', markup: 0 });
});

/* ------------------------------------------------------------------ */
/* Log viewer                                                          */
/* ------------------------------------------------------------------ */

const LOGS = {
    entries: [
        { timestamp: '2026-11-10T11:59:58.123Z', level: 'ERROR', logger: 'bridge.ingest', message: 'decode failed', exception: 'Traceback: ValueError' },
        { timestamp: 'yesterday', level: 'INFO', logger: 'bridge.api', message: 'started' },
        { level: 'DEBUG', logger: 'bridge.ws', message: 'no timestamp' },
    ],
    loggers: ['bridge.ingest', 'bridge.api'],
};

test('the log viewer shows each entry\'s time, level, logger, message and exception', async () => {
    const page = await adminPage({ routes: { 'GET /api/admin/logs': () => reply(200, LOGS) } });
    await page.tab('logs');
    assert.deepEqual(gets(page, '/api/admin/logs'), ['/api/admin/logs?limit=300']);
    const entries = page.byId('log-entries').querySelectorAll('.log-entry');
    assert.deepEqual(entries.map(e => [e.querySelector('.log-ts').textContent, e.querySelector('.log-level').textContent,
        e.querySelector('.log-logger').textContent, e.querySelector('.log-msg').textContent]), [
        ['11:59:58', 'ERROR', 'bridge.ingest', 'decode failedTraceback: ValueError'],
        ['yesterday', 'INFO', 'bridge.api', 'started'],
        ['', 'DEBUG', 'bridge.ws', 'no timestamp'],
    ]);
    assert.equal(entries[0].querySelector('.log-exc').textContent, 'Traceback: ValueError');
    assert.equal(entries[1].querySelector('.log-exc'), null);
    assert.ok(entries[0].querySelector('.log-level').classList.contains('ERROR'));
    assert.equal(page.byId('log-empty').style.display, 'none');
    assert.deepEqual(page.byId('log-logger-filter').options.map(o => o.value), ['', 'bridge.ingest', 'bridge.api']);
});

test('log filters reload the viewer with level, logger and search; the logger choice survives the reload', async () => {
    let answer = LOGS;
    const page = await adminPage({ routes: { 'GET /api/admin/logs': () => reply(200, answer) } });
    await page.tab('logs');
    await page.change(page.byId('log-level-filter'), 'ERROR');
    await page.change(page.byId('log-logger-filter'), 'bridge.api');
    assert.equal(page.byId('log-logger-filter').value, 'bridge.api', 'the rebuilt logger list keeps the choice');
    page.byId('log-search').value = 'decode';
    await page.key('d', page.byId('log-search'));
    await page.key('Enter', page.byId('log-search'));
    answer = { entries: [] };
    await page.click(page.byId('log-refresh-btn'));
    assert.deepEqual(gets(page, '/api/admin/logs'), [
        '/api/admin/logs?limit=300',
        '/api/admin/logs?limit=300&level=ERROR',
        '/api/admin/logs?limit=300&level=ERROR&logger=bridge.api',
        '/api/admin/logs?limit=300&level=ERROR&logger=bridge.api&search=decode',
        '/api/admin/logs?limit=300&level=ERROR&logger=bridge.api&search=decode',
    ], 'other keys in the search box do not reload');
    assert.equal(page.byId('log-entries').innerHTML, '');
    assert.equal(page.byId('log-empty').style.display, '');
    assert.deepEqual(page.byId('log-logger-filter').options.map(o => o.value), ['', 'bridge.ingest', 'bridge.api'],
        'a reply without a logger list leaves the list as it was');
});

test('auto-refresh reloads the logs every 5 seconds until it is switched off', async () => {
    const page = await adminPage({ routes: { 'GET /api/admin/logs': () => reply(200, LOGS) } });
    await page.tab('logs');
    const auto = page.byId('log-auto-refresh');
    await page.advance(10000);
    assert.equal(gets(page, '/api/admin/logs').length, 1, 'no polling until asked');
    auto.checked = true;
    await page.change(auto, 'on');
    await page.advance(15000);
    assert.equal(gets(page, '/api/admin/logs').length, 4);
    auto.checked = false;
    await page.change(auto, 'on');
    await page.advance(15000);
    assert.equal(gets(page, '/api/admin/logs').length, 4);
    await page.change(auto, 'on');
    assert.equal(gets(page, '/api/admin/logs').length, 4, 'switching off twice is harmless');
});

/* ------------------------------------------------------------------ */
/* System                                                              */
/* ------------------------------------------------------------------ */

function systemRoutes(extra = {}) {
    return {
        'GET /api/metrics': () => reply(200, {}),
        'GET /api/admin/config': () => reply(200, {}),
        'GET /api/admin/sessions': () => reply(200, { sessions: [] }),
        'GET /api/admin/session-binding': () => reply(200, { saved: 'none', gateway_active: 'none', restart_required: false }),
        ...extra,
    };
}
const metricCards = page => page.byId('system-metrics').querySelectorAll('.metric-card')
    .map(card => card.querySelector('.metric-value').textContent + ' ' + card.querySelector('.metric-label').textContent);

test('system metrics: uptime, ingest rate, database size and live connections, with placeholders for the unreported', async () => {
    let metrics = { uptime_seconds: 90061, ingest: { detections_per_second: 12.345 }, database: { db_size_mb: 512.26 },
        ws_clients: { detections: 2, anomalies: 0, spectrum: 1, wifi: 3 } };
    const page = await adminPage({ routes: systemRoutes({ 'GET /api/metrics': () => (metrics ? reply(200, metrics) : reply(503)) }) });
    await page.tab('system');
    assert.deepEqual(metricCards(page), ['1d 1h 1m Uptime', '12.3/s Ingest Rate', '512.3 MB DB Size', '2 WS Detections',
        '0 WS Anomalies', '1 WS Spectrum', '3 WS WiFi']);
    metrics = { uptime_seconds: 3599 };
    await page.tab('system');
    assert.deepEqual(metricCards(page), ['59m Uptime', '-- Ingest Rate', '-- DB Size', '-- WS Detections', '-- WS Anomalies',
        '-- WS Spectrum', '-- WS WiFi']);
    metrics = { uptime_seconds: -1 };
    await page.tab('system');
    assert.equal(metricCards(page)[0], '-- Uptime');
    metrics = null;
    await page.tab('system');
    assert.equal(page.byId('system-metrics').textContent, 'Metrics unavailable');
});

test('metrics auto-refresh polls every 10 seconds until it is switched off', async () => {
    const page = await adminPage({ routes: systemRoutes() });
    await page.tab('system');
    const auto = page.byId('metrics-auto-refresh');
    auto.checked = true;
    await page.change(auto, 'on');
    await page.advance(30000);
    assert.equal(gets(page, '/api/metrics').length, 4);
    auto.checked = false;
    await page.change(auto, 'on');
    await page.advance(30000);
    assert.equal(gets(page, '/api/metrics').length, 4);
});

test('the retention policy card says whether the retention comes from the environment or the default', async () => {
    let retention = { retention_days: 30, source: 'env' };
    const page = await adminPage({ routes: systemRoutes({ 'GET /api/admin/config': () => reply(200, { retention }) }) });
    await page.tab('system');
    const badge = page.byId('retention-source-badge');
    assert.deepEqual([page.byId('retention-days-value').textContent, badge.textContent, badge.style.background],
        ['30', 'ENV', 'var(--accent-green)']);
    retention = { retention_days: 7, source: 'default' };
    await page.tab('system');
    assert.deepEqual([page.byId('retention-days-value').textContent, badge.textContent, badge.style.background],
        ['7', 'DEFAULT', 'var(--accent-blue)']);
    assert.equal(page.byId('system-sessions').textContent, 'No active sessions');
});

test('a session binding the server cannot report says it failed to load', async () => {
    const page = await adminPage({ routes: systemRoutes({ 'GET /api/admin/session-binding': () => reply(500) }) });
    await page.tab('system');
    assert.equal(page.byId('session-binding-status').textContent, 'Failed to load: HTTP 500');
    page.allowConsoleErrors(); // the failure is also logged for developers
});

test('a backup or maintenance task refused without an explanation reports its HTTP status', async () => {
    const page = await databaseTab({ routes: { 'POST /api/admin/backup': () => reply(500), 'POST /api/admin/maintenance': () => reply(500) } });
    await page.click(page.byId('backup-create-btn'));
    assert.equal(page.byId('backup-result').textContent, 'Failed: HTTP 500');
    const result = await runTask(page, 'optimize');
    assert.equal(result.textContent, 'Failed: HTTP 500');
    const optimize = page.doc.querySelector('.maint-task-btn[data-task="optimize"]');
    assert.deepEqual([optimize.disabled, optimize.textContent], [false, 'Optimize (ANALYZE)'], 'a failed task gives its button back');
});
