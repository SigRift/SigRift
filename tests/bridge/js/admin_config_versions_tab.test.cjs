/* The admin console's Config Versions tab (admin.js): configuration
 * snapshots (list, view, create, restore, delete) and the line diff between
 * two snapshots or a snapshot and the live configuration, driven through the
 * controls of templates/admin.html in the admin_dom.cjs stub DOM. */
const assert = require('node:assert/strict');
const test = require('node:test');
const { adminPage, noUnexpectedConsoleErrors, reply, assertCookieWrite, call, cell } = require('./admin_dom.cjs');

test.afterEach(noUnexpectedConsoleErrors);

const lastToast = page => page.toasts().at(-1);
const SNAPSHOTS = [
    { id: 3, timestamp: '2026-11-10T11:00:00Z', trigger: 'manual', description: 'pre-deploy', file_count: 4 },
    { id: 2, timestamp: '2026-11-09T03:00:00Z', trigger: 'daily', file_count: 4 },
    { id: 1, timestamp: '2026-11-08T03:00:00Z', trigger: 'pre-restore', file_count: 3 },
];

/* The version tab, its server holding `snapshots` (the list) and `stored`
 * (id -> snapshot, as GET /api/admin/config-snapshots/<id> returns it). */
async function versionTab({ snapshots = SNAPSHOTS, stored = {}, routes = {} } = {}) {
    const server = { snapshots, stored };
    const table = {
        'GET /api/admin/config-snapshots': () => reply(200, { snapshots: server.snapshots }),
        ...routes,
    };
    for (const id of [1, 2, 3, 9]) {
        table['GET /api/admin/config-snapshots/' + id] ||= () => (server.stored[id] ? reply(200, { snapshot: server.stored[id] }) : reply(404, { detail: 'Snapshot not found' }));
    }
    const page = await adminPage({ routes: table });
    page.server = server;
    await page.tab('version');
    return page;
}
const box = (page, id) => page.byId('config-snap-tbody').querySelector('[data-snap-cmp="' + id + '"]');
async function tick(page, id, checked) {
    const el = box(page, id);
    el.checked = checked;
    await page.change(el, 'on');
}
const selection = page => ({
    text: page.byId('config-cmp-sel').textContent,
    compare: page.byId('config-cmp-btn').disabled, current: page.byId('config-cmp-current-btn').disabled,
    checked: SNAPSHOTS.map(s => box(page, s.id).checked),
});

test('the snapshot list shows each snapshot\'s trigger, description and file count; an empty store says so', async () => {
    const page = await versionTab();
    assert.equal(page.byId('config-snap-empty').style.display, 'none');
    assert.equal(page.byId('config-snap-table').style.display, '');
    const rows = page.byId('config-snap-tbody').querySelectorAll('tr');
    assert.deepEqual(rows.map(row => ['ID', 'Trigger', 'Description', 'Files'].map(label => cell(row, label).textContent)),
        [['3', 'manual', 'pre-deploy', '4'], ['2', 'daily', '--', '4'], ['1', 'pre-restore', '--', '3']]);
    assert.deepEqual(rows.map(row => cell(row, 'Trigger').firstChild.style.color),
        ['var(--accent-blue)', 'var(--accent-green)', 'var(--accent-orange, #d29922)']);
    assert.equal(cell(rows[0], 'Timestamp').textContent, page.context.fmtTime(SNAPSHOTS[0].timestamp));

    page.server.snapshots = [];
    await page.tab('version');
    assert.equal(page.byId('config-snap-tbody').innerHTML, '');
    assert.equal(page.byId('config-snap-empty').style.display, '');
    assert.equal(page.byId('config-snap-table').style.display, 'none');
});

test('choosing snapshots to compare: at most two, the earliest choice gives way, and the buttons follow the choice', async () => {
    const page = await versionTab();
    assert.deepEqual([page.byId('config-cmp-btn').disabled, page.byId('config-cmp-current-btn').disabled], [true, true]);
    await tick(page, 3, true);
    assert.deepEqual(selection(page), {
        text: 'Selected: #3 — select one more to compare, or compare vs current config.', compare: true, current: false,
        checked: [true, false, false],
    });
    await tick(page, 2, true);
    assert.deepEqual(selection(page), { text: 'Selected: #3 vs #2', compare: false, current: false, checked: [true, true, false] });
    await tick(page, 1, true);
    assert.deepEqual(selection(page), { text: 'Selected: #2 vs #1', compare: false, current: false, checked: [false, true, true] });
    await tick(page, 2, false);
    assert.deepEqual(selection(page).text, 'Selected: #1 — select one more to compare, or compare vs current config.');
    assert.deepEqual(selection(page).checked, [false, false, true]);

    // A reloaded list keeps the choice ticked.
    await page.tab('version');
    assert.deepEqual(selection(page).checked, [false, false, false], 'opening the tab starts a new choice');
    await tick(page, 2, true);
    page.routes['POST /api/admin/config-snapshots'] = () => reply(201, { snapshot_id: 4 });
    await page.click(page.byId('config-snap-create-btn'));
    await page.click(page.button('Create'));
    assert.deepEqual(selection(page).checked, [false, true, false]);

    page.byId('config-cmp-result').innerHTML = '<p>old diff</p>';
    await page.click(page.byId('config-cmp-clear-btn'));
    assert.deepEqual(selection(page), {
        text: 'Select up to two snapshots using the checkboxes in the table above.', compare: true, current: true,
        checked: [false, false, false],
    });
    assert.equal(page.byId('config-cmp-result').innerHTML, '');
});

test('viewing a snapshot lists its files with their sizes, cutting a large file short', async () => {
    const page = await versionTab({
        stored: {
            3: { id: 3, timestamp: '2026-11-10T11:00:00Z', trigger: 'manual', description: 'pre-deploy',
                files: { 'b.json': { mode: 'ip' }, 'a.txt': 'plain text', 'big.json': 'x'.repeat(2500) } },
            2: { id: 2, timestamp: '2026-11-09T03:00:00Z', trigger: 'daily', files: {} },
        },
    });
    const detail = page.byId('config-snap-detail');
    page.byId('config-snap-tbody').querySelector('[data-snap-view="3"]').click();
    assert.equal(detail.textContent, 'Loading snapshot #3...');
    await page.advance(0);
    assert.equal(detail.firstChild.textContent, 'Snapshot #3 — ' + page.context.fmtTime('2026-11-10T11:00:00Z') + ' — manual — pre-deploy');
    const files = detail.querySelectorAll('details').map(d => [d.querySelector('summary').textContent, d.querySelector('pre').textContent]);
    assert.deepEqual(files.map(([summary]) => summary), ['a.txt (10 chars)', 'b.json (18 chars)', 'big.json (2500 chars)']);
    assert.equal(files[0][1], 'plain text');
    assert.equal(files[1][1], JSON.stringify({ mode: 'ip' }, null, 2), 'stored JSON is shown indented');
    assert.ok(files[2][1] === 'x'.repeat(2000) + '\n... (truncated)', 'a large file shows its first 2000 characters');

    await page.click(page.byId('config-snap-tbody').querySelector('[data-snap-view="2"]'));
    assert.equal(detail.firstChild.textContent, 'Snapshot #2 — ' + page.context.fmtTime('2026-11-09T03:00:00Z') + ' — daily');
    assert.equal(detail.querySelector('.empty-state').textContent, 'No files in this snapshot');

    page.routes['GET /api/admin/config-snapshots/1'] = () => reply(200, { snapshot: null });
    await page.click(page.byId('config-snap-tbody').querySelector('[data-snap-view="1"]'));
    assert.equal(detail.textContent, 'Snapshot not found');
    page.routes['GET /api/admin/config-snapshots/1'] = () => reply(500);
    await page.click(page.byId('config-snap-tbody').querySelector('[data-snap-view="1"]'));
    assert.equal(detail.textContent, 'Failed to load snapshot: HTTP 500');
});

test('creating a snapshot asks for an optional description, then reports the new snapshot for a few seconds', async () => {
    let refuse = false;
    const page = await versionTab({
        routes: { 'POST /api/admin/config-snapshots': () => (refuse ? reply(507, { detail: 'disk full' }) : reply(201, { snapshot_id: 4 })) },
    });
    const result = page.byId('config-snap-result');
    await page.click(page.byId('config-snap-create-btn'));
    assert.equal(page.doc.activeElement, page.modal().querySelector('#admin-modal-snap-desc'));
    await page.click(page.button('Cancel'));
    assert.deepEqual(page.writes(), []);

    await page.click(page.byId('config-snap-create-btn'));
    page.modal().querySelector('#admin-modal-snap-desc').value = 'before firmware update';
    const lists = page.requests.filter(r => r.url.startsWith('/api/admin/config-snapshots?')).length;
    await page.click(page.button('Create'));
    const [created] = page.writes();
    assert.deepEqual(call(created), ['POST', '/api/admin/config-snapshots', { description: 'before firmware update' }]);
    assertCookieWrite(created);
    assert.deepEqual([result.style.display, result.textContent], ['', 'Snapshot #4 created.']);
    assert.equal(page.requests.filter(r => r.url.startsWith('/api/admin/config-snapshots?')).length, lists + 1, 'the list is reloaded');
    await page.advance(4000);
    assert.equal(result.style.display, 'none');

    refuse = true;
    await page.click(page.byId('config-snap-create-btn'));
    await page.click(page.button('Create'));
    assert.deepEqual(page.writes()[1].body, { description: '' });
    assert.deepEqual([result.style.display, result.textContent], ['', 'Failed: disk full']);
});

test('restoring a snapshot needs confirmation and lists what it restored; a refusal says why', async () => {
    let answer = () => reply(200, { restored_files: ['bridge.json', 'alerts.json'] });
    const page = await versionTab({ routes: { 'POST /api/admin/config-snapshots/3/restore': () => answer() } });
    const result = page.byId('config-snap-result');
    const restore = () => page.click(page.byId('config-snap-tbody').querySelector('[data-snap-restore="3"]'));
    await restore();
    assert.match(page.modal().textContent, /Restore config from snapshot #3\?.*A pre-restore backup will be created automatically\./s);
    await page.click(page.button('Cancel'));
    assert.deepEqual(page.writes(), []);
    await restore();
    await page.click(page.button('Restore'));
    assert.deepEqual(call(page.writes()[0]), ['POST', '/api/admin/config-snapshots/3/restore', undefined]);
    assert.equal(result.textContent, 'Restored 2 files from snapshot #3: bridge.json, alerts.json');

    answer = () => reply(200, {});
    await restore();
    await page.click(page.button('Restore'));
    assert.equal(result.textContent, 'Restored 0 files from snapshot #3: ');

    answer = () => reply(409, { detail: 'incomplete snapshot' });
    await restore();
    await page.click(page.button('Restore'));
    assert.equal(result.textContent, 'Restore failed: incomplete snapshot');
    assert.deepEqual(lastToast(page), { text: 'Restore failed: incomplete snapshot', type: 'error', markup: 0 });
});

test('deleting a snapshot needs confirmation; a refusal says why', async () => {
    let refuse = true;
    const page = await versionTab({ routes: { 'DELETE /api/admin/config-snapshots/2': () => (refuse ? reply(500) : reply(204)) } });
    const remove = () => page.click(page.byId('config-snap-tbody').querySelector('[data-snap-delete="2"]'));
    await remove();
    await page.key('Escape');
    assert.deepEqual(page.writes(), []);
    await remove();
    await page.click(page.button('Delete'));
    assert.deepEqual(lastToast(page), { text: 'Delete failed: HTTP 500', type: 'error', markup: 0 });
    refuse = false;
    await remove();
    await page.click(page.button('Delete'));
    assert.deepEqual(lastToast(page), { text: 'Snapshot #2 deleted', type: 'success', markup: 0 });
    assert.deepEqual(page.writes().map(call), Array(2).fill(['DELETE', '/api/admin/config-snapshots/2', undefined]));
});

/* ------------------------------------------------------------------ */
/* Compare                                                             */
/* ------------------------------------------------------------------ */

/* The compare result as read: the summary line, then per file its name,
 * status and the diff lines with their +/- markers. */
function diffOf(page) {
    const el = page.byId('config-cmp-result');
    return {
        summary: el.firstChild.textContent,
        files: el.querySelectorAll('details').map(d => ({
            file: d.querySelector('summary code').textContent,
            status: d.querySelector('summary span').textContent,
            open: d.hasAttribute('open'),
            lines: d.querySelector('div').children.map(line => line.textContent.replace(/^\d+/, '')),
        })),
    };
}

const SNAP_A = { id: 2, timestamp: '2026-11-09T03:00:00Z', files: {
    'same.json': { a: 1 }, 'changed.json': { mode: 'ip', level: 2 }, 'gone.txt': 'old', 'text.txt': 'a\nb\nc',
} };
const SNAP_B = { id: 3, timestamp: '2026-11-10T11:00:00Z', files: {
    'same.json': { a: 1 }, 'changed.json': { mode: 'strict', level: 2 }, 'new.txt': 'fresh', 'text.txt': 'a\nc\nd',
} };

async function compareStored(a, b) {
    const page = await versionTab({ stored: { 2: a, 3: b } });
    await tick(page, 2, true);
    await tick(page, 3, true);
    page.byId('config-cmp-btn').click();
    assert.equal(page.byId('config-cmp-result').textContent, 'Loading snapshots #2 and #3...');
    await page.advance(0);
    return page;
}
const without = (snapshot, ...names) => ({ ...snapshot, files: Object.fromEntries(Object.entries(snapshot.files).filter(([name]) => !names.includes(name))) });

test('comparing two snapshots shows each file unchanged or changed, line by line', async () => {
    const page = await compareStored(without(SNAP_A, 'gone.txt'), without(SNAP_B, 'new.txt'));
    assert.deepEqual(diffOf(page), {
        summary: '4 changes across 3 files',
        files: [
            { file: 'changed.json', status: '2 changes', open: true, lines: ['  {', '-   "mode": "ip",', '+   "mode": "strict",', '    "level": 2', '  }'] },
            { file: 'same.json', status: 'unchanged', open: false, lines: ['  {', '    "a": 1', '  }'] },
            { file: 'text.txt', status: '2 changes', open: true, lines: ['  a', '- b', '  c', '+ d'] },
        ],
    });
    const header = page.byId('config-cmp-result').querySelectorAll('strong').map(el => el.textContent);
    assert.deepEqual(header.slice(1, 3), ['#2', '#3']);
});

test('a file only one of the snapshots has is marked added or removed, with its lines', async () => {
    const page = await compareStored(SNAP_A, SNAP_B);
    const files = Object.fromEntries(diffOf(page).files.map(file => [file.file, file]));
    assert.deepEqual(Object.keys(files), ['changed.json', 'gone.txt', 'new.txt', 'same.json', 'text.txt']);
    assert.deepEqual([files['gone.txt'].status, files['gone.txt'].open], ['removed', true]);
    assert.ok(files['gone.txt'].lines.includes('- old'));
    assert.deepEqual([files['new.txt'].status, files['new.txt'].open], ['added', true]);
    assert.ok(files['new.txt'].lines.includes('+ fresh'));
    assert.match(diffOf(page).summary, / across 5 files$/);
});

test('an added or removed file counts only its own lines as changes', async () => {
    const page = await compareStored({ id: 2, files: { 'gone.txt': 'old' } }, { id: 3, files: {} });
    assert.deepEqual(diffOf(page).files[0].lines, ['- old']);
    assert.equal(diffOf(page).summary, '1 change across 1 file');
});

test('an added JSON file shows only its own lines, all as additions', async () => {
    const page = await compareStored({ id: 2, files: {} }, { id: 3, files: { 'new.json': { a: 1 } } });
    assert.deepEqual(diffOf(page).files[0].lines, ['+ {', '+   "a": 1', '+ }']);
    assert.equal(diffOf(page).files[0].status, 'added');
    assert.equal(diffOf(page).summary, '3 changes across 1 file');
});

test('comparing ignores timestamps and live metrics unless asked not to', async () => {
    const node = (cpu, seen) => ({ id: 'edge-1', cpu_percent: cpu, memory_mb: 100 + cpu, last_seen: seen, mode: 'scan' });
    const a = { id: 2, files: { 'state.json': { saved_at: 't1', nodes: [node(10, 'x')] }, 'notes.txt': 'saved_at: t1' } };
    const b = { id: 3, files: { 'state.json': { saved_at: 't2', nodes: [node(90, 'y')] }, 'notes.txt': 'saved_at: t1' } };
    const page = await versionTab({ stored: { 2: a, 3: b } });
    await tick(page, 2, true);
    await tick(page, 3, true);
    const compare = async () => { await page.click(page.byId('config-cmp-btn')); return diffOf(page); };
    assert.deepEqual((await compare()).summary, '0 changes across 2 files');
    page.byId('config-cmp-ignore-ts').checked = false;
    const withTimes = await compare();
    assert.equal(withTimes.summary, '2 changes across 2 files');
    assert.deepEqual(withTimes.files[1].lines.filter(line => /^[-+]/.test(line)), ['-   "saved_at": "t1",', '+   "saved_at": "t2",']);
    page.byId('config-cmp-ignore-metrics').checked = false;
    assert.equal((await compare()).summary, '8 changes across 2 files');
    page.byId('config-cmp-ignore-ts').checked = true;
    assert.equal((await compare()).summary, '6 changes across 2 files');
});

test('two snapshots without files compare as nothing to show', async () => {
    const page = await versionTab({ stored: { 2: { id: 2 }, 3: { id: 3, files: {} } } });
    await tick(page, 2, true);
    await tick(page, 3, true);
    await page.click(page.byId('config-cmp-btn'));
    assert.equal(page.byId('config-cmp-result').firstChild.textContent, '0 changes across 0 files');
    assert.equal(page.byId('config-cmp-result').querySelector('.empty-state').textContent, 'No files in either snapshot');
});

test('a very large file is compared position by position instead of by line matching', async () => {
    const lines = Array.from({ length: 2500 }, (_, i) => 'line ' + i);
    const a = { id: 2, files: { 'big.txt': lines.join('\n') } };
    const b = { id: 3, files: { 'big.txt': ['inserted', ...lines].join('\n') } };
    const page = await versionTab({ stored: { 2: a, 3: b } });
    await tick(page, 2, true);
    await tick(page, 3, true);
    await page.click(page.byId('config-cmp-btn'));
    // One inserted line shifts every position: each old line is removed and re-added.
    assert.equal(page.byId('config-cmp-result').firstChild.textContent, '5001 changes across 1 file');
    const first = page.byId('config-cmp-result').querySelector('details div').children.slice(0, 3).map(line => line.textContent.replace(/^\d+/, ''));
    assert.deepEqual(first, ['- line 0', '+ inserted', '- line 1']);

    // A small file with the same insertion is matched line by line: one change.
    const small = lines.slice(0, 10);
    page.server.stored = { 2: { id: 2, files: { 'big.txt': small.join('\n') } }, 3: { id: 3, files: { 'big.txt': ['inserted', ...small].join('\n') } } };
    await page.click(page.byId('config-cmp-btn'));
    assert.equal(page.byId('config-cmp-result').firstChild.textContent, '1 change across 1 file');
});

test('a snapshot that no longer exists cannot be compared, and the list is reloaded', async () => {
    const page = await versionTab({ stored: { 2: SNAP_A } });
    await tick(page, 2, true);
    await tick(page, 3, true);
    const lists = () => page.requests.filter(r => r.url.startsWith('/api/admin/config-snapshots?')).length;
    const before = lists();
    await page.click(page.byId('config-cmp-btn'));
    assert.equal(page.byId('config-cmp-result').textContent, 'Snapshot #3 no longer exists. It may have been deleted or auto-purged.');
    assert.equal(lists(), before + 1);
    page.server.stored = {};
    await page.click(page.byId('config-cmp-btn'));
    // Both missing snapshots are named (whatever the grammar of the sentence).
    assert.match(page.byId('config-cmp-result').textContent, /^Snapshots? #2 and #3 no longer exists?\b/);
});

test('comparing with the live config takes a temporary snapshot, compares against it, then deletes it', async () => {
    const live = { id: 9, timestamp: '2026-11-10T12:00:00Z', trigger: 'manual', files: { 'same.json': { a: 2 } } };
    let create = () => reply(201, { snapshot_id: 9 });
    const page = await versionTab({
        stored: { 3: { id: 3, files: { 'same.json': { a: 1 } } }, 9: live },
        routes: { 'POST /api/admin/config-snapshots': () => create(), 'DELETE /api/admin/config-snapshots/9': () => reply(204) },
    });
    await tick(page, 3, true);
    page.byId('config-cmp-current-btn').click();
    assert.equal(page.byId('config-cmp-result').textContent, 'Loading snapshot #3 and current config...');
    await page.advance(0);
    assert.deepEqual(page.writes().map(call), [
        ['POST', '/api/admin/config-snapshots', { description: '(temp compare)' }],
        ['DELETE', '/api/admin/config-snapshots/9', undefined],
    ]);
    const diff = diffOf(page);
    assert.equal(diff.summary, '2 changes across 1 file');
    assert.deepEqual(page.byId('config-cmp-result').querySelectorAll('strong').slice(1, 3).map(el => el.textContent), ['#3', '#current']);

    // The chosen snapshot is gone: say so, and still remove the temporary one.
    delete page.server.stored[3];
    await page.click(page.byId('config-cmp-current-btn'));
    assert.equal(page.byId('config-cmp-result').textContent, 'Snapshot #3 no longer exists. It may have been deleted or auto-purged.');
    assert.equal(page.writes().at(-1).method, 'DELETE');

    page.server.stored = { 3: { id: 3, files: {} } };
    await page.click(page.byId('config-cmp-current-btn'));
    assert.equal(page.byId('config-cmp-result').textContent, 'Failed to read current config snapshot.');
    assert.equal(page.writes().at(-1).method, 'DELETE');

    create = () => reply(500);
    const writes = page.writes().length;
    await page.click(page.byId('config-cmp-current-btn'));
    assert.equal(page.byId('config-cmp-result').textContent, 'Failed to create current config snapshot: HTTP 500');
    assert.equal(page.writes().length, writes + 1, 'nothing to delete when no snapshot was made');
});

test('a snapshot change refused without an explanation reports its HTTP status', async () => {
    const page = await versionTab({
        routes: { 'POST /api/admin/config-snapshots': () => reply(500), 'POST /api/admin/config-snapshots/3/restore': () => reply(500) },
    });
    await page.click(page.byId('config-snap-create-btn'));
    await page.click(page.button('Create'));
    assert.equal(page.byId('config-snap-result').textContent, 'Failed: HTTP 500');
    await page.click(page.byId('config-snap-tbody').querySelector('[data-snap-restore="3"]'));
    await page.click(page.button('Restore'));
    assert.equal(page.byId('config-snap-result').textContent, 'Restore failed: HTTP 500');
    assert.deepEqual(lastToast(page), { text: 'Restore failed: HTTP 500', type: 'error', markup: 0 });
});
