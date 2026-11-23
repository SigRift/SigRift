const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const test = require('node:test');
const vm = require('node:vm');
const {
    buildBaseline, verifyBaseline, inlineEntries, instrument, canonical, hash,
} = require('./static_coverage.cjs');

function fixture(t, files = {}) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sigrift-static-coverage-'));
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    function write(name, source) {
        const target = path.join(root, name);
        fs.mkdirSync(path.dirname(target), { recursive: true });
        fs.writeFileSync(target, source);
    }
    for (const name of ['inventory.py', 'static_coverage.cjs', 'package.json', 'package-lock.json']) {
        write(`tests/bridge/js/${name}`, fs.readFileSync(path.join(__dirname, name)));
    }
    write('src/app.js', 'function dormant(flag) { if (flag) return 1; return 2; }\n');
    for (const [name, source] of Object.entries(files)) write(name, source);
    const git = (...args) => execFileSync('git', ['-c', 'user.name=Coverage fixture', '-c',
        'user.email=coverage@example.invalid', '-c', 'commit.gpgsign=false', ...args], { cwd: root, stdio: 'pipe' });
    git('init', '-q');
    git('add', '.');
    git('commit', '-qm', 'Static coverage fixture');
    return { root, write, git };
}

function entry(code, grammar = 'script') {
    return { id: 'fixture.js', source_path: 'fixture.js', kind: 'file', code, grammar };
}

function reseal(manifest) {
    delete manifest.manifest_sha256;
    manifest.manifest_sha256 = hash(canonical(manifest));
}

test('authored test drivers retain uncalled helpers and zero static alternatives', t => {
    const driver = 'tests/bridge/js/mixed.test.cjs';
    const { root } = fixture(t, { [driver]:
        "require('node:test')('no-op', () => {});\n"
        + "function cleanup(failed) { if (failed) throw new Error('unused'); return 1; }\n"
        + "throw new Error('Discovery must not execute this driver');\n" });
    const result = buildBaseline(root);
    const record = result.entries.find(entry => entry.id === driver);
    assert.ok(record, 'Collected test driver was omitted from the authored denominator');
    assert.deepEqual(Object.values(record.coverage.branchMap).map(branch => branch.type), ['if']);
    assert.ok(Object.values(record.coverage.s).every(count => count === 0));
    assert.ok(Object.values(record.coverage.b).flat().every(count => count === 0));
    assert.deepEqual(result.inventory.collected_test_exclusions, []);
});

test('static maps include uncalled nested branches without evaluating source', () => {
    const { record } = instrument(entry(`
        throw new Error('This code must never execute during discovery');
        function neverCalled(x) {
            if (x) { return function nested(y) { return y ? 1 : 2; }; }
            return x || 3;
        }
    `));
    assert.deepEqual(Object.values(record.coverage.branchMap).map(branch => branch.type).sort(),
        ['binary-expr', 'cond-expr', 'if']);
    assert.equal(Object.keys(record.coverage.fnMap).length, 2);
    assert.ok(Object.values(record.coverage.s).every(count => count === 0));
    assert.ok(Object.values(record.coverage.f).every(count => count === 0));
    assert.ok(Object.values(record.coverage.b).flat().every(count => count === 0));
});

test('actual generated counters execute under disabled string code generation', () => {
    const { generated, record } = instrument(entry('globalThis.choose = x => x ? 11 : 22;'));
    const context = vm.createContext({}, { codeGeneration: { strings: false, wasm: false } });
    vm.runInContext(generated, context);
    assert.equal(context.choose(true), 11);
    assert.equal(context.choose(false), 22);
    const actual = context.__sigrift_static_coverage__['fixture.js'];
    assert.deepEqual(Array.from(Object.values(actual.b)[0]), [1, 1]);
    assert.deepEqual(Object.values(record.coverage.b)[0], [0, 0]);
    assert.match(generated, /globalThis/);
    assert.doesNotMatch(generated, /new Function/);
});

test('Unicode/entity decoding preserves duplicate inline origins and handler semantics', () => {
    const source = '😀<button onclick="return event.ok &amp;&amp; this.enabled">A</button>'
        + '<button onclick="return event.ok &amp;&amp; this.enabled">B</button>'
        + '<script>if (ready) launch()</script><script>if (ready) launch()</script>';
    const entries = inlineEntries('src/page.html', source);
    assert.equal(entries.length, 4);
    assert.equal(new Set(entries.map(item => item.id)).size, 4);
    assert.equal(entries[0].code, 'return event.ok && this.enabled');
    assert.equal(entries[0].inventory_identity.column, 2); // Python uses Unicode scalar columns.
    assert.equal(source.slice(entries[0].origin.start, entries[0].origin.end),
        'onclick="return event.ok &amp;&amp; this.enabled"');
    const first = instrument(entries[0]);
    const second = instrument(entries[1]);
    assert.equal(first.record.body_sha256, second.record.body_sha256);
    assert.notEqual(first.record.id, second.record.id);
    const context = vm.createContext({}, { codeGeneration: { strings: false } });
    const handler = vm.runInContext(`(function(event) { ${first.generated}\n })`, context);
    assert.equal(handler.call({ enabled: 'selected' }, { ok: true }), 'selected');
    assert.equal(handler.call({ enabled: 'selected' }, { ok: false }), false);
});

test('raw script bodies do not HTML-decode entities; templates retain dormant behavior', () => {
    const entries = inlineEntries('src/page.html', '<!-- <script>notCode()</script> -->'
        + '<script type="application/json">{"x":true}</script>'
        + '<template><script>const x = "&amp;";</script><button onclick="run()">x</button></template>');
    assert.equal(entries.length, 2);
    assert.equal(entries[0].code, 'const x = "&amp;";');
    assert.equal(entries[1].kind, 'event-handler');
});

for (const pragma of ['istanbul ignore next', 'istanbul ignore if', 'istanbul ignore file',
    'c8 ignore next', 'v8 ignore start', 'node:coverage disable']) {
    test(`suppression comment is rejected: ${pragma}`, () => {
        assert.throws(() => instrument(entry(`/* ${pragma} */ if (a) b();`)), /suppression/);
    });
}

test('text resembling a pragma in a string is not an exclusion', () => {
    assert.ok(instrument(entry('const help = "istanbul ignore next";')).record.coverage.s);
});

test('syntax errors and precompiled maps fail instead of producing empty maps', () => {
    assert.throws(() => instrument(entry('function broken( {')), SyntaxError);
    assert.throws(() => instrument(entry('run();\n//# sourceMappingURL=app.js.map')), /explicit adapter/);
});

test('preinstrumented maps cannot hide newly appended executable branches', () => {
    const original = instrument(entry('function oldFunction(x) { if (x) return 1; return 2; }'));
    const changed = original.generated + '\nfunction newFunction(y) { return y ? 3 : 4; }';
    assert.throws(() => instrument(entry(changed)), /Already instrumented/);
});

test('ambiguous HTML and unsupported execution grammars fail closed', () => {
    assert.throws(() => inlineEntries('x.html', '<button onclick="a()" onclick="b()">x</button>'), /Duplicate/);
    assert.throws(() => inlineEntries('x.html', '<script>neverClosed()'), /Unclosed/);
    assert.throws(() => inlineEntries('x.html', '<script type="new-language">x()</script>'), /Unsupported/);
    assert.throws(() => inlineEntries('x.html', '<a href="java&#10;script:run()">x</a>'), /source adapter/);
});

test('module and event-handler parse rules are explicit', () => {
    assert.equal(instrument(entry('export const value = x => x ? 1 : 0;', 'module')).record.grammar, 'module');
    assert.throws(() => instrument(entry('return true;')), SyntaxError);
    assert.doesNotThrow(() => instrument(entry('return true;', 'event-handler')));
});

test('real repository inventory seeds unloaded helpers and inline bodies at zero', t => {
    const { root } = fixture(t, {
        'tools/never-loaded.mjs': 'export function nested(x) { return x ? 1 : 2; }',
        'tests/helper.js': 'function helper(x) { if (x) return 1; return 0; }',
        'tests/bridge/js/collected.test.cjs': "require('node:test')('example', () => {});",
        'src/page.html': '😀<button onclick="return event.ok &amp;&amp; this.enabled">A</button>',
    });
    const result = buildBaseline(root);
    assert.equal(result.status, 'baseline-only-no-execution');
    assert.equal(result.source.dirty, false);
    assert.equal(result.inventory.inline_behaviors, 1);
    assert.ok(result.inventory.files.includes('tests/helper.js'));
    assert.ok(result.inventory.files.includes('tests/bridge/js/static_coverage.cjs'));
    assert.ok(result.inventory.files.includes('tests/bridge/js/collected.test.cjs'));
    assert.deepEqual(result.inventory.collected_test_exclusions, []);
    const unloaded = result.entries.find(item => item.id === 'tools/never-loaded.mjs');
    assert.deepEqual(Object.values(unloaded.coverage.b), [[0, 0]]);
    for (const metric of ['lines', 'statements', 'functions', 'branches']) {
        assert.ok(result.totals[metric].total > 0);
        assert.equal(result.totals[metric].covered, 0);
        assert.equal(result.totals[metric].skipped, 0);
    }
    assert.equal(verifyBaseline(JSON.parse(JSON.stringify(result)), root).manifest_sha256, result.manifest_sha256);
});

test('source, inventory, map and counter tampering invalidate a resealed manifest', t => {
    const { root, write } = fixture(t);
    const baseline = buildBaseline(root);
    for (const mutate of [
        result => { result.entries[0].coverage.statementMap['0'].start.column += 1; },
        result => { result.entries[0].coverage.s['0'] = 1; },
        result => { result.entries.pop(); },
        result => { result.measurement.instrumenter_options.ignoreClassMethods = ['uncovered']; },
        result => { result.measurement.node = 'v0.0.0'; },
    ]) {
        const altered = structuredClone(baseline);
        mutate(altered);
        reseal(altered);
        assert.throws(() => verifyBaseline(altered, root), /differs/);
    }
    write('src/app.js', 'function dormant(flag) { if (flag) return 9; return 8; }\n');
    assert.throws(() => verifyBaseline(baseline, root, { allowDirty: true }), /differs/);
    write('src/new.js', 'function neverLoaded(x) { return x ? 1 : 0; }');
    assert.throws(() => verifyBaseline(baseline, root, { allowDirty: true }), /differs/);
});

test('checksum is checked before reconstruction', t => {
    const { root } = fixture(t);
    const baseline = buildBaseline(root);
    baseline.manifest_sha256 = '0'.repeat(64);
    assert.throws(() => verifyBaseline(baseline, root), /checksum/);
});

test('dirty measurement configuration cannot inherit clean source provenance', t => {
    const { root, write } = fixture(t);
    const baseline = buildBaseline(root);
    write('tests/bridge/js/package-lock.json', fs.readFileSync(path.join(__dirname, 'package-lock.json'), 'utf8') + '\n');
    assert.throws(() => buildBaseline(root), /Dirty/);
    const development = buildBaseline(root, { allowDirty: true });
    assert.equal(development.source.dirty, true);
    assert.notEqual(development.manifest_sha256, baseline.manifest_sha256);
    assert.throws(() => verifyBaseline(baseline, root, { allowDirty: true }), /differs/);
});

test('assume-unchanged configuration is still compared with exact committed bytes', t => {
    const { root, write, git } = fixture(t);
    git('update-index', '--assume-unchanged', 'tests/bridge/js/package-lock.json');
    write('tests/bridge/js/package-lock.json', fs.readFileSync(path.join(__dirname, 'package-lock.json'), 'utf8') + '\n');
    assert.equal(git('status', '--porcelain').toString(), '');
    assert.throws(() => buildBaseline(root), /Dirty/);
    assert.equal(buildBaseline(root, { allowDirty: true }).source.dirty, true);
});

test('installed tool version must match the exact locked version', t => {
    const { root, write } = fixture(t);
    const packageInfo = JSON.parse(fs.readFileSync(path.join(root, 'tests/bridge/js/package.json')));
    packageInfo.devDependencies['istanbul-lib-instrument'] = '6.0.2';
    const lock = JSON.parse(fs.readFileSync(path.join(root, 'tests/bridge/js/package-lock.json')));
    lock.packages[''].devDependencies['istanbul-lib-instrument'] = '6.0.2';
    lock.packages['node_modules/istanbul-lib-instrument'].version = '6.0.2';
    write('tests/bridge/js/package.json', JSON.stringify(packageInfo));
    write('tests/bridge/js/package-lock.json', JSON.stringify(lock));
    assert.throws(() => buildBaseline(root, { allowDirty: true }), /dependency mismatch/);
});

test('a loaded collector cannot attest a replacement of its own on-disk implementation', t => {
    const { root, write } = fixture(t);
    fs.symlinkSync(path.join(__dirname, 'node_modules'), path.join(root, 'tests/bridge/js/node_modules'));
    const target = path.join(root, 'tests/bridge/js/static_coverage.cjs');
    const loaded = require(target);
    write('tests/bridge/js/static_coverage.cjs', fs.readFileSync(target, 'utf8') + '\n// A later implementation revision.\n');
    assert.throws(() => loaded.buildBaseline(root, { allowDirty: true }), /Running static collector differs/);
});

test('deleted and symlinked authored files are not silently omitted', t => {
    const { root } = fixture(t);
    fs.unlinkSync(path.join(root, 'src/app.js'));
    assert.throws(() => buildBaseline(root, { allowDirty: true }), /inventory mismatch/);
    fs.symlinkSync('../tests/bridge/js/static_coverage.cjs', path.join(root, 'src/app.js'));
    assert.throws(() => buildBaseline(root, { allowDirty: true }), /Symlink/);
});

for (const [removed, source] of [
    ['tests/bridge/js/helper.test.cjs', 'function dormant(x) { return x ? 1 : 2; }'],
    ['src/page.html', '<script>if (ready) launch()</script>'],
]) {
    test(`staged deletion cannot inherit clean measurement provenance: ${removed}`, t => {
        const { root, git } = fixture(t, { [removed]: source });
        const before = buildBaseline(root);
        git('rm', '--', removed);
        assert.throws(() => buildBaseline(root), /Dirty/);
        const development = buildBaseline(root, { allowDirty: true });
        assert.equal(development.source.dirty, true);
        assert.ok(!development.source.inputs.some(input => input.path === removed));
        assert.throws(() => verifyBaseline(before, root, { allowDirty: true }), /differs/);
    });
}

test('real CLI refuses source, tracked, symlink and hardlink output aliases without changes', t => {
    const { root, git } = fixture(t, { 'reports/coverage/javascript-static/tracked.json': '{}' });
    fs.symlinkSync(path.join(__dirname, 'node_modules'), path.join(root, 'tests/bridge/js/node_modules'));
    const app = path.join(root, 'src/app.js');
    const original = fs.readFileSync(app);
    const reports = path.join(root, 'reports/coverage/javascript-static');
    fs.symlinkSync(path.join(root, 'src'), path.join(reports, 'linked-parent'));
    fs.symlinkSync(app, path.join(reports, 'linked-file.json'));
    fs.linkSync(app, path.join(reports, 'hardlink.json'));
    fs.unlinkSync(path.join(reports, 'tracked.json')); // A tracked deletion is not a new report destination.
    for (const output of [
        'src/app.js', 'tests/bridge/js/package-lock.json',
        'reports/coverage/javascript-static/tracked.json',
        'reports/coverage/javascript-static/linked-parent/replacement.json',
        'reports/coverage/javascript-static/linked-file.json',
        'reports/coverage/javascript-static/hardlink.json',
    ]) {
        assert.throws(() => execFileSync(process.execPath,
            ['tests/bridge/js/static_coverage.cjs', '--allow-dirty', `--output=${output}`],
            { cwd: root, stdio: 'pipe' }), error => error.status === 1
                && /Write a new JSON|Refusing/.test(error.stderr.toString()));
        assert.deepEqual(fs.readFileSync(app), original);
    }
    assert.equal(fs.existsSync(path.join(root, 'src/replacement.json')), false);
    assert.equal(fs.existsSync(path.join(reports, 'tracked.json')), false);
    assert.ok(git('status', '--porcelain').toString().includes('D reports/coverage/javascript-static/tracked.json'));
});

test('real CLI writes and verifies the serialized zero baseline including implicit else locations', t => {
    const { root } = fixture(t);
    fs.symlinkSync(path.join(__dirname, 'node_modules'), path.join(root, 'tests/bridge/js/node_modules'));
    const report = 'reports/coverage/javascript-static/baseline.json';
    const run = argument => JSON.parse(execFileSync(process.execPath,
        ['tests/bridge/js/static_coverage.cjs', argument], { cwd: root, encoding: 'utf8' }));
    const written = run(`--output=${report}`);
    const checked = run(`--verify-baseline=${report}`);
    assert.deepEqual(checked, written);
    assert.equal(checked.status, 'baseline-only-no-execution');
    assert.equal(checked.dirty, false);
    assert.ok(checked.totals.branches.total > 0);
    assert.equal(checked.totals.branches.covered, 0);
});
