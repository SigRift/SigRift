const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const { execFileSync, spawnSync } = require('node:child_process');
const test = require('node:test');
const { verifyInventory, completeCounters } = require('./coverage.cjs');

const root = path.resolve('/fixture');
const file = name => path.join(root, 'src', name);
const measured = (total, covered) => ({ lines: { total, covered } });

test('real c8 collection measures test helpers and retains uncollected authored tests', t => {
    const fixture = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'sigrift-all-authored-js-')));
    t.after(() => fs.rmSync(fixture, { recursive: true, force: true }));
    const directory = path.join(fixture, 'tests/bridge/js');
    fs.mkdirSync(directory, { recursive: true });
    for (const name of ['coverage.cjs', 'inventory.py']) {
        fs.copyFileSync(path.join(__dirname, name), path.join(directory, name));
    }
    fs.symlinkSync(path.join(__dirname, 'node_modules'), path.join(directory, 'node_modules'));
    fs.writeFileSync(path.join(directory, 'mixed.test.cjs'),
        "const test = require('node:test');\nconst assert = require('node:assert/strict');\n"
        + "function helper(flag) { if (flag) return 1; return 2; }\n"
        + "test('one behavioral arm', () => assert.equal(helper(true), 1));\n");
    fs.writeFileSync(path.join(directory, 'uncollected.test.mjs'),
        'export function dormant(flag) { if (flag) return 1; return 2; }\n');
    execFileSync('git', ['init', '-q', fixture]);
    const env = { ...process.env };
    // This fixture launches a separate real suite, not recursive node:test.
    delete env.NODE_TEST_CONTEXT;
    delete env.NODE_V8_COVERAGE;
    const result = spawnSync(process.execPath, [path.join(directory, 'coverage.cjs'), '--report-only'],
        { cwd: fixture, env, encoding: 'utf8', timeout: 30000 });
    assert.ifError(result.error);
    assert.equal(result.status, 0, result.stderr + result.stdout);
    const reports = path.join(fixture, 'reports/coverage/javascript');
    const summary = JSON.parse(fs.readFileSync(path.join(reports, 'coverage-summary.json')));
    const inventory = JSON.parse(fs.readFileSync(path.join(reports, 'inventory.json')));
    assert.deepEqual(inventory.test_exclusions, []);
    const driver = summary[path.join(directory, 'mixed.test.cjs')];
    assert.ok(driver.lines.covered > 0, result.stdout + result.stderr);
    assert.ok(driver.branches.covered > 0 && driver.branches.covered < driver.branches.total);
    const dormant = summary[path.join(directory, 'uncollected.test.mjs')];
    assert.ok(dormant.lines.total > 0);
    assert.equal(dormant.lines.covered, 0);
    assert.equal(completeCounters(summary, inventory.files, fixture,
        inventory.unmeasured_branch_files), false);
});

test('an unexecuted source remains in the inventory at zero coverage', () => {
    verifyInventory({
        [file('executed.js')]: measured(10, 10),
        [file('unexecuted.js')]: measured(40, 0),
    }, ['src/executed.js', 'src/unexecuted.js'], root);
});

test('a newly added but unreported source fails the coverage inventory', () => {
    assert.throws(() => verifyInventory({
        [file('executed.js')]: measured(10, 10),
    }, ['src/executed.js', 'src/new.js'], root), /missing=.*new.js/);
});

test('an empty coverage report cannot report a successful inventory', () => {
    assert.throws(() => verifyInventory({ total: measured(0, 0) }, [], root), /No first-party/);
    assert.throws(() => verifyInventory({}, ['src/executed.js'], root), /missing=/);
});

test('unexpected vendor files and zero-line source entries fail', () => {
    assert.throws(() => verifyInventory({
        [file('executed.js')]: measured(10, 10),
        [file('vendor.js')]: measured(500, 500),
    }, ['src/executed.js'], root), /unexpected=.*vendor.js/);
    assert.throws(() => verifyInventory({
        [file('executed.js')]: measured(0, 0),
    }, ['src/executed.js'], root), /omitted executable lines/);
});

function completeReport() {
    const counters = {
        lines: { total: 100000, covered: 100000, skipped: 0, pct: 100 },
        branches: { total: 100000, covered: 100000, skipped: 0, pct: 100 },
    };
    return { [file('executed.js')]: structuredClone(counters), total: structuredClone(counters) };
}

test('rounded 100 percent cannot conceal one uncovered line or branch', () => {
    for (const metric of ['lines', 'branches']) {
        const report = completeReport();
        assert.equal(completeCounters(report, ['src/executed.js'], root), true);
        report[file('executed.js')][metric].covered -= 1;
        report.total[metric].covered -= 1;
        assert.equal(completeCounters(report, ['src/executed.js'], root), false);
    }
});

test('missing, fractional, negative, excessive and excluded counters fail closed', () => {
    for (const metric of ['lines', 'branches']) {
        for (const invalid of [undefined, { total: 1 },
            { total: 2, covered: 1.5, skipped: 0 },
            { total: 2, covered: -1, skipped: 0 },
            { total: 2, covered: 3, skipped: 0 },
            { total: 2, covered: 2, skipped: 1 }]) {
            const report = completeReport();
            report[file('executed.js')][metric] = invalid;
            assert.throws(() => completeCounters(report, ['src/executed.js'], root), /Invalid or excluded/);
        }
    }
});

test('aggregate counters must equal the complete file inventory', () => {
    for (const metric of ['lines', 'branches']) {
        for (const key of ['total', 'covered', 'skipped']) {
            const report = completeReport();
            report.total[metric][key] += 1;
            assert.throws(() => completeCounters(report, ['src/executed.js'], root), /Invalid .* totals/);
        }
        const report = completeReport();
        delete report.total[metric];
        assert.throws(() => completeCounters(report, ['src/executed.js'], root), /Invalid .* totals/);
    }
});

test('the floor comparison is exact and is not rounded up', () => {
    const { meetsFloor } = require('./coverage.cjs');
    assert.equal(meetsFloor(297, 1000, 29.7), true);
    assert.equal(meetsFloor(296, 1000, 29.7), false);
    // 29.69999...% rounds to 29.70 for display but must not pass a 29.7 floor.
    assert.equal(meetsFloor(2969999, 10000000, 29.7), false);
    assert.equal(meetsFloor(0, 10, 0), true);
    assert.equal(meetsFloor(10, 10, 100), true);
    assert.equal(meetsFloor(9, 10, 100), false);
    assert.throws(() => meetsFloor(1, 2, -1), /Invalid coverage floor/);
    assert.throws(() => meetsFloor(1, 2, 1e-7), /Invalid coverage floor/);
});

test('the release gate passes at the floor and fails below either metric', () => {
    const { checkFloors } = require('./coverage.cjs');
    const summary = (lines, branches) => ({ total: {
        lines: { covered: lines, total: 100 }, branches: { covered: branches, total: 100 },
    } });
    const floors = { lines: 30, branches: 85 };
    assert.equal(checkFloors(summary(30, 85), floors).passed, true);
    assert.equal(checkFloors(summary(29, 99), floors).passed, false);
    assert.equal(checkFloors(summary(99, 84), floors).passed, false);
    assert.deepEqual(checkFloors(summary(30, 85), floors).floor, floors);
});

test('missing or malformed floors fail closed', t => {
    const { loadFloors } = require('./coverage.cjs');
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sigrift-floors-'));
    t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
    const write = value => {
        const target = path.join(directory, `${Math.random()}.json`);
        fs.writeFileSync(target, typeof value === 'string' ? value : JSON.stringify(value));
        return target;
    };
    assert.deepEqual(loadFloors(write({ javascript: { lines: 1, branches: 2 } })), { lines: 1, branches: 2 });
    assert.throws(() => loadFloors(path.join(directory, 'absent.json')), /Missing or invalid/);
    assert.throws(() => loadFloors(write('{')), /Missing or invalid/);
    assert.throws(() => loadFloors(write({ python: { lines: 1, branches: 2 } })), /need lines and branches/);
    assert.throws(() => loadFloors(write({ javascript: { lines: 1 } })), /need lines and branches/);
    assert.throws(() => loadFloors(write({ javascript: { lines: 1, branches: 2, extra: 3 } })), /need lines and branches/);
    assert.throws(() => loadFloors(write({ javascript: { lines: '1', branches: 2 } })), /Invalid javascript lines/);
    assert.throws(() => loadFloors(write({ javascript: { lines: 1, branches: 101 } })), /Invalid javascript branches/);
});

test('the committed repository floors are valid', () => {
    const { loadFloors } = require('./coverage.cjs');
    const floors = loadFloors();
    assert.ok(floors.lines > 0 && floors.branches > 0);
});
