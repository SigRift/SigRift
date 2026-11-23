const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createHash } = require('node:crypto');
const test = require('node:test');
const { browserReports, unmeasuredBranchFunctions, unmeasuredBranchFiles, completeCounters } = require('./coverage.cjs');
const v8ToIstanbul = require('v8-to-istanbul');

function fixture(t, source = 'function login() { return true; }\nlogin();\n') {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sigrift-js-coverage-'));
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    const relative = 'src/login.js';
    fs.mkdirSync(path.join(root, 'src'));
    fs.mkdirSync(path.join(root, 'private'));
    fs.writeFileSync(path.join(root, relative), source);
    const report = {
        result: [{ scriptId: '1', url: relative, functions: [{
            functionName: 'login', isBlockCoverage: true,
            ranges: [{ startOffset: 0, endOffset: source.length, count: 2 }],
        }] }],
        sigrift: { complete: true, source_sha256: {
            [relative]: createHash('sha256').update(source).digest('hex'),
        } },
    };
    const save = () => fs.writeFileSync(path.join(root, 'private/coverage-browser-fixture.json'), JSON.stringify(report));
    save();
    return { root, relative, report, save, read: () => browserReports(path.join(root, 'private'), [relative], root) };
}

test('verified browser counts map to the exact repository source', async t => {
    const f = fixture(t);
    const reports = f.read();
    assert.equal(reports[0].result[0].url, path.join(f.root, f.relative));
    assert.equal(reports[0].result[0].functions[0].ranges[0].count, 2);
    assert.equal(reports[0].sigrift, undefined);
    const converter = v8ToIstanbul(path.join(f.root, f.relative));
    await converter.load();
    converter.applyCoverage(reports[0].result[0].functions);
    const converted = converter.toIstanbul()[path.join(f.root, f.relative)];
    assert.ok(Object.values(converted.b).some(counts => counts.some(count => count > 0)));
});

test('changed source and unknown source paths cannot contribute browser coverage', t => {
    const f = fixture(t);
    f.report.sigrift.source_sha256[f.relative] = 'wrong'; f.save();
    assert.throws(f.read, /source hash differs/);
    f.report.result[0].url = '../outside.js'; f.save();
    assert.throws(f.read, /outside the inventory/);
});

test('missing, incomplete and invalid coverage reports fail closed', t => {
    const f = fixture(t);
    f.report.sigrift.complete = false; f.save();
    assert.throws(f.read, /incomplete/);
    f.report.sigrift.complete = true;
    f.report.result[0].functions[0].ranges[0].count = -1; f.save();
    assert.throws(f.read, /Invalid browser coverage range/);
    fs.rmSync(path.join(f.root, 'private/coverage-browser-fixture.json'));
    assert.throws(f.read, /No browser coverage reports/);
});

test('function-only executed coverage cannot claim lines without branch evidence', async t => {
    const f = fixture(t, 'function choose(x) {\n  if (x) return 1;\n  return 2;\n}\nchoose(true);\n');
    f.report.result[0].functions[0].isBlockCoverage = false;
    f.save();
    // Exercise the actual converter: function-only counts mark the source
    // covered while supplying no branch outcomes at all.
    const converter = v8ToIstanbul(path.join(f.root, f.relative));
    await converter.load();
    converter.applyCoverage(f.report.result[0].functions);
    const converted = converter.toIstanbul()[path.join(f.root, f.relative)];
    assert.ok(Object.values(converted.s).every(count => count > 0));
    assert.equal(Object.keys(converted.b).length, 0);
    assert.throws(f.read, /Executed function lacks block coverage/);
});

test('missing block-coverage metadata cannot certify browser execution', t => {
    const f = fixture(t);
    delete f.report.result[0].functions[0].isBlockCoverage;
    f.save();
    assert.throws(f.read, /Missing browser block-coverage metadata/);
});

test('genuine unexecuted V8 functions retain uncovered lines and unknown branches', async t => {
    const f = fixture(t);
    f.report.result[0].functions[0].isBlockCoverage = false;
    f.report.result[0].functions[0].ranges[0].count = 0;
    f.save();
    const reports = f.read();
    const converter = v8ToIstanbul(path.join(f.root, f.relative));
    await converter.load();
    converter.applyCoverage(reports[0].result[0].functions);
    const converted = converter.toIstanbul()[path.join(f.root, f.relative)];
    assert.ok(Object.values(converted.s).every(count => count === 0));
    assert.equal(Object.keys(converted.b).length, 0);
    const unknown = unmeasuredBranchFunctions(reports, [f.relative], f.root);
    assert.deepEqual(unknown, [{ path: f.relative, startOffset: 0, endOffset: fs.readFileSync(path.join(f.root, f.relative), 'utf8').length }]);
    // Even an otherwise numerically complete aggregate cannot prove that the
    // missing internal branches of an unexecuted function were measured.
    const counters = { lines: { total: 1, covered: 1, skipped: 0 }, branches: { total: 1, covered: 1, skipped: 0 } };
    const summary = { [path.join(f.root, f.relative)]: counters, total: counters };
    assert.equal(completeCounters(summary, [f.relative], f.root, unknown), false);
});

test('later precise execution resolves only the same source function range', t => {
    const f = fixture(t);
    const measured = f.read();
    const uncovered = structuredClone(measured);
    uncovered[0].result[0].functions[0].isBlockCoverage = false;
    uncovered[0].result[0].functions[0].ranges[0].count = 0;
    assert.equal(unmeasuredBranchFunctions(uncovered, [f.relative], f.root).length, 1);
    assert.deepEqual(unmeasuredBranchFunctions([...uncovered, ...measured], [f.relative], f.root), []);
    measured[0].result[0].functions[0].ranges[0].endOffset -= 1;
    assert.equal(unmeasuredBranchFunctions([...uncovered, ...measured], [f.relative], f.root).length, 1);
});

test('an unloaded source cannot borrow branch evidence from another file', t => {
    const f = fixture(t);
    const reports = f.read();
    assert.deepEqual(unmeasuredBranchFiles(reports, [f.relative, 'src/unloaded.js'], f.root), ['src/unloaded.js']);
    reports[0].result[0].url = require('node:url').pathToFileURL(reports[0].result[0].url).href;
    assert.deepEqual(unmeasuredBranchFiles(reports, [f.relative], f.root), []);
});
