/* Opt-in Node AST execution evidence. This does not replace a release gate. */
const fs = require('node:fs');
const path = require('node:path');
const { spawn, spawnSync } = require('node:child_process');
const { randomUUID } = require('node:crypto');
const { createCoverageMap } = require('istanbul-lib-coverage');
const { readInitialCoverage } = require('istanbul-lib-instrument');
const { MAGIC_KEY, MAGIC_VALUE } = require('istanbul-lib-instrument/src/constants');
const { buildBaseline, instrument, canonical, hash } = require('./static_coverage.cjs');

const ROOT = path.resolve(__dirname, '../../..');
const DIRECTORY = 'tests/bridge/js';
const SELF = `${DIRECTORY}/static_execution.cjs`;
const PRELOAD = `${DIRECTORY}/static_execution_preload.cjs`;
const BOOTSTRAP = `${DIRECTORY}/static_execution_bootstrap.cjs`;
const SELF_HASH = hash(fs.readFileSync(__filename));
const GLOBAL = '__sigrift_static_coverage__';
const clone = value => JSON.parse(JSON.stringify(value));
const same = (left, right) => canonical(left) === canonical(right);

function seal(value) { return { ...value, checksum: hash(canonical(value)) }; }
function unseal(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Missing evidence object');
    const { checksum, ...payload } = value;
    if (checksum !== hash(canonical(payload))) throw new Error('Evidence checksum mismatch');
    return payload;
}
function keys(value, expected, label) {
    if (!value || typeof value !== 'object' || Array.isArray(value)
        || !same(Object.keys(value).sort(), [...expected].sort())) throw new Error(`Invalid ${label} keys`);
}
function safeCount(value) {
    if (!Number.isSafeInteger(value) || value < 0) throw new Error('Counter must be a nonnegative safe integer');
    return value;
}
function add(left, right) {
    const total = safeCount(left) + safeCount(right);
    if (!Number.isSafeInteger(total)) throw new Error('Counter overflow while merging evidence');
    return total;
}
function git(root, args) {
    const result = spawnSync('git', args, { cwd: root, encoding: 'utf8', timeout: 60000 });
    if (result.error || result.status !== 0) throw new Error('Git source verification failed');
    return result.stdout;
}
function readBound(root, relative) {
    if (path.isAbsolute(relative) || relative.split('/').some(part => !part || part === '..')) throw new Error('Invalid source path');
    let current = root;
    for (const part of relative.split('/')) {
        current = path.join(current, part);
        if (fs.lstatSync(current).isSymbolicLink()) throw new Error('Symlink source is unsupported');
    }
    return fs.readFileSync(current);
}
function testSources(root, baseline, allowDirty) {
    const names = fs.readdirSync(path.join(root, DIRECTORY)).filter(name => name.endsWith('.test.cjs')).sort();
    if (!names.length) throw new Error('No Node tests collected');
    const tests = names.map(name => {
        const relative = `${DIRECTORY}/${name}`;
        return { path: relative, sha256: hash(readBound(root, relative)) };
    });
    const tracked = new Set(git(root, ['ls-tree', '-r', '--name-only', baseline.source.commit]).split('\n'));
    const trackedTests = [...tracked].filter(name => name.startsWith(`${DIRECTORY}/`)
        && name.slice(DIRECTORY.length + 1).endsWith('.test.cjs')
        && !name.slice(DIRECTORY.length + 1).includes('/')).sort();
    const dirty = !same(trackedTests, tests.map(test => test.path)) || tests.some(test => !tracked.has(test.path)
        || hash(git(root, ['show', `${baseline.source.commit}:${test.path}`])) !== test.sha256);
    if (dirty && !allowDirty) throw new Error('Dirty test driver inputs');
    return { tests, dirty };
}
function createPlan(root = ROOT, { allowDirty = false } = {}) {
    root = fs.realpathSync(root);
    const baseline = buildBaseline(root, { allowDirty });
    if (hash(readBound(root, SELF)) !== SELF_HASH) throw new Error('Loaded execution collector differs from source');
    const drivers = testSources(root, baseline, allowDirty);
    const programs = baseline.entries.filter(entry => entry.kind === 'file').map(record => {
        const code = readBound(root, record.source_path).toString('utf8');
        const actual = instrument({ id: record.id, source_path: record.source_path, kind: 'file', grammar: record.grammar, code });
        if (!same(record, actual.record)) throw new Error('Generated execution source differs from baseline');
        const initial = readInitialCoverage(actual.generated);
        if (!initial || initial.gcv !== GLOBAL || !same(initial.coverageData, record.coverage)) throw new Error('Invalid generated counter initialization');
        return { id: record.id, generated: actual.generated, runtime_hash: initial.hash };
    });
    return seal({ schema: 'sigrift-node-ast-plan-v2', run_id: randomUUID(), root, baseline,
        producer: { execution_sha256: SELF_HASH, preload_sha256: hash(readBound(root, PRELOAD)), bootstrap_sha256: hash(readBound(root, BOOTSTRAP)), node: process.version },
        test_sources: drivers.tests, tests_dirty: drivers.dirty, programs });
}
function verifyPlan(plan, root = plan.root, { allowDirty = false } = {}) {
    const data = unseal(plan);
    keys(data, ['schema', 'run_id', 'root', 'baseline', 'producer', 'test_sources', 'tests_dirty', 'programs'], 'plan');
    if (data.schema !== 'sigrift-node-ast-plan-v2' || !/^[0-9a-f-]{36}$/.test(data.run_id)
        || fs.realpathSync(root) !== data.root) throw new Error('Invalid execution plan identity');
    const rebuilt = createPlan(root, { allowDirty });
    const comparable = clone(rebuilt);
    comparable.run_id = plan.run_id;
    delete comparable.checksum;
    if (!same(seal(comparable), plan)) throw new Error('Execution plan differs from source, tests, maps or toolchain');
    return plan;
}
function validateCounts(actual, expected) {
    keys(actual, ['s', 'f', 'b'], 'counter groups');
    for (const group of ['s', 'f', 'b']) {
        keys(actual[group], Object.keys(expected[group]), `${group} counter`);
        for (const key of Object.keys(expected[group])) {
            if (group === 'b') {
                const value = actual.b[key];
                if (!Array.isArray(value) || value.length !== expected.b[key].length
                    || Object.keys(value).length !== value.length) throw new Error('Missing or extra branch alternatives');
                value.forEach(safeCount);
            } else safeCount(actual[group][key]);
        }
    }
    return clone(actual);
}
function snapshotCounters(actual, record, program) {
    const expected = record.coverage;
    keys(actual, [...Object.keys(expected), MAGIC_KEY, 'hash'], 'runtime coverage');
    for (const key of Object.keys(expected).filter(key => !['s', 'f', 'b'].includes(key))) {
        if (!same(actual[key], expected[key])) throw new Error('Runtime coverage map/source mismatch');
    }
    if (actual[MAGIC_KEY] !== MAGIC_VALUE || actual.hash !== program.runtime_hash) throw new Error('Generated runtime hash mismatch');
    return validateCounts({ s: actual.s, f: actual.f, b: actual.b }, expected);
}
function identity(plan, worker) {
    return { run_id: plan.run_id, baseline_sha256: plan.baseline.manifest_sha256,
        plan_sha256: plan.checksum, producer: plan.producer, worker: { ...worker, launch_id: worker.launch_id ?? null } };
}
function validateIdentity(plan, report) {
    if (!same({ run_id: report.run_id, baseline_sha256: report.baseline_sha256,
        plan_sha256: report.plan_sha256, producer: report.producer },
    { run_id: plan.run_id, baseline_sha256: plan.baseline.manifest_sha256,
        plan_sha256: plan.checksum, producer: plan.producer })) throw new Error('Incompatible execution evidence');
    keys(report.worker, ['pid', 'thread_id', 'nonce', 'test_path', 'launch_id'], 'worker identity');
    if (!Number.isSafeInteger(report.worker.pid) || report.worker.pid <= 0
        || !Number.isSafeInteger(report.worker.thread_id) || report.worker.thread_id < 0
        || !/^[0-9a-f-]{36}$/.test(report.worker.nonce)
        || !(report.worker.launch_id === null || /^[0-9a-f-]{36}$/.test(report.worker.launch_id))
        || !(report.worker.test_path === null || plan.test_sources.some(test => test.path === report.worker.test_path))) {
        throw new Error('Invalid worker identity');
    }
}
function workerKey(worker) { return `${worker.pid}-${worker.thread_id}-${worker.nonce}`; }
function mergeReceipts(plan, registrations, receipts, evaluations, options = {}) {
    verifyPlan(plan, plan.root, options);
    if (!registrations.length || !receipts.length) throw new Error('Missing registered execution evidence');
    const workers = new Map();
    for (const registration of registrations) {
        const payload = unseal(registration);
        keys(payload, ['schema', 'run_id', 'baseline_sha256', 'plan_sha256', 'producer', 'worker'], 'registration');
        validateIdentity(plan, payload);
        if (payload.schema !== 'sigrift-node-ast-registration-v2') throw new Error('Unknown registration schema');
        const key = workerKey(payload.worker);
        if (workers.has(key)) throw new Error('Duplicate worker registration');
        workers.set(key, payload.worker);
    }
    const launches = new Map();
    for (const launch of options.launches || []) {
        const payload = unseal(launch);
        keys(payload, ['schema', 'run_id', 'baseline_sha256', 'plan_sha256', 'producer', 'worker', 'launch_id', 'kind'], 'launch');
        validateIdentity(plan, payload);
        if (payload.schema !== 'sigrift-node-ast-launch-v2' || !workers.has(workerKey(payload.worker))
            || !same(workers.get(workerKey(payload.worker)), payload.worker)
            || !/^[0-9a-f-]{36}$/.test(payload.launch_id) || launches.has(payload.launch_id)
            || !['process', 'thread'].includes(payload.kind)) throw new Error('Invalid or duplicate child launch');
        launches.set(payload.launch_id, { ...payload, children: 0 });
    }
    for (const worker of workers.values()) if (worker.launch_id !== null) {
        const launch = launches.get(worker.launch_id);
        if (!launch || ++launch.children !== 1
            || (launch.kind === 'thread' ? worker.pid !== launch.worker.pid || worker.thread_id === 0 : worker.pid === launch.worker.pid || worker.thread_id !== 0)) {
            throw new Error('Unbound child worker registration');
        }
    }
    if ([...launches.values()].some(launch => launch.children !== 1)) throw new Error('Missing launched worker registration');
    const records = new Map(plan.baseline.entries.map(record => [record.id, record]));
    if (!Array.isArray(evaluations)) throw new Error('Missing evaluation journal');
    const expectedContexts = new Map([...workers.keys()].map(key => [key, new Map()]));
    for (const evaluation of evaluations) {
        const payload = unseal(evaluation);
        keys(payload, ['schema', 'run_id', 'baseline_sha256', 'plan_sha256', 'producer', 'worker',
            'context_id', 'id', 'body_sha256', 'generated_sha256', 'map_sha256', 'evaluation'], 'evaluation');
        validateIdentity(plan, payload);
        const key = workerKey(payload.worker);
        const record = records.get(payload.id);
        if (payload.schema !== 'sigrift-node-ast-evaluation-v2' || !workers.has(key)
            || !same(workers.get(key), payload.worker) || !record || record.kind !== 'file'
            || payload.body_sha256 !== record.body_sha256 || payload.generated_sha256 !== record.generated_sha256
            || payload.map_sha256 !== record.map_sha256 || !Number.isSafeInteger(payload.context_id) || payload.context_id < 0
            || !Number.isSafeInteger(payload.evaluation) || payload.evaluation < 1) throw new Error('Invalid evaluation identity');
        const contexts = expectedContexts.get(key);
        if (!contexts.has(payload.context_id)) contexts.set(payload.context_id, new Map());
        const entries = contexts.get(payload.context_id);
        if (!entries.has(payload.id)) entries.set(payload.id, new Set());
        const numbers = entries.get(payload.id);
        if (numbers.has(payload.evaluation)) throw new Error('Duplicate evaluation journal entry');
        numbers.add(payload.evaluation);
    }
    for (const contexts of expectedContexts.values()) for (const entries of contexts.values()) {
        for (const numbers of entries.values()) {
            if ([...numbers].some(value => value > numbers.size)) throw new Error('Missing evaluation journal entry');
        }
    }
    const merged = new Map(plan.baseline.entries.map(record => [record.id, clone(record.coverage)]));
    const observed = new Set();
    const seen = new Set();
    const failures = [];
    let contexts = 0;
    for (const receipt of receipts) {
        const payload = unseal(receipt);
        keys(payload, ['schema', 'run_id', 'baseline_sha256', 'plan_sha256', 'producer', 'worker', 'exit_code', 'contexts', 'error'], 'receipt');
        validateIdentity(plan, payload);
        const key = workerKey(payload.worker);
        if (payload.schema !== 'sigrift-node-ast-receipt-v2' || !workers.has(key)
            || !same(workers.get(key), payload.worker) || seen.has(key)) throw new Error('Unknown or duplicate execution receipt');
        seen.add(key);
        if (!Number.isInteger(payload.exit_code) || payload.exit_code < 0 || payload.exit_code > 255) throw new Error('Invalid worker exit status');
        if (payload.error !== null) throw new Error('Collector reported invalid or missing counters');
        if (payload.exit_code !== 0) failures.push(key);
        if (!Array.isArray(payload.contexts)) throw new Error('Missing context inventory');
        const expected = expectedContexts.get(key);
        const contextIds = new Set();
        for (const context of payload.contexts) {
            keys(context, ['context_id', 'entries'], 'context');
            if (!Number.isSafeInteger(context.context_id) || context.context_id < 0
                || contextIds.has(context.context_id) || !Array.isArray(context.entries) || !context.entries.length) throw new Error('Invalid context identity');
            const journal = expected.get(context.context_id);
            if (!journal) throw new Error('Unknown context in final receipt');
            contextIds.add(context.context_id); contexts++;
            const ids = new Set();
            for (const entry of context.entries) {
                keys(entry, ['id', 'body_sha256', 'generated_sha256', 'map_sha256', 'evaluations', 'counts'], 'execution entry');
                const record = records.get(entry.id);
                if (!record || record.kind !== 'file' || ids.has(entry.id)) throw new Error('Unknown or duplicate executed source');
                ids.add(entry.id); observed.add(entry.id);
                if (entry.body_sha256 !== record.body_sha256 || entry.generated_sha256 !== record.generated_sha256
                    || entry.map_sha256 !== record.map_sha256 || !Number.isSafeInteger(entry.evaluations) || entry.evaluations < 1) throw new Error('Execution source/generated/map identity mismatch');
                if (!journal.has(entry.id) || journal.get(entry.id).size !== entry.evaluations) throw new Error('Receipt differs from evaluation journal');
                const counts = validateCounts(entry.counts, record.coverage);
                const target = merged.get(entry.id);
                for (const group of ['s', 'f', 'b']) for (const counter of Object.keys(counts[group])) {
                    target[group][counter] = group === 'b'
                        ? target.b[counter].map((value, index) => add(value, counts.b[counter][index]))
                        : add(target[group][counter], counts[group][counter]);
                }
            }
            if (ids.size !== journal.size) throw new Error('Missing source in final receipt');
        }
        if (contextIds.size !== expected.size) throw new Error('Missing context in final receipt');
    }
    if (seen.size !== workers.size) throw new Error('Missing final worker receipt');
    const tests = new Set([...workers.values()].map(worker => worker.test_path).filter(Boolean));
    if (!same([...tests].sort(), plan.test_sources.map(test => test.path).sort())) throw new Error('Missing test-worker registration');
    const map = createCoverageMap({});
    for (const coverage of merged.values()) map.addFileCoverage(coverage);
    const totals = map.getCoverageSummary().toJSON();
    const complete = ['lines', 'branches'].every(metric => totals[metric].total > 0
        && totals[metric].covered === totals[metric].total && totals[metric].skipped === 0);
    return { coverage: Object.fromEntries(merged), totals, observed_sources: [...observed].sort(), contexts,
        workers: workers.size, launched_workers: launches.size, failed_workers: failures,
        failed_test_workers: failures.filter(key => workers.get(key).launch_id === null && workers.get(key).test_path !== null),
        ast_counters_complete: complete,
        unobserved_sources: plan.baseline.entries.map(record => record.id).filter(id => !observed.has(id)) };
}
function destination(relative, root = ROOT) {
    root = fs.realpathSync(root);
    const target = path.resolve(root, relative);
    const base = path.join(root, 'reports/coverage/javascript-static');
    if (!target.startsWith(base + path.sep) || path.extname(target) !== '.json') throw new Error('Write a new JSON result under reports/coverage/javascript-static');
    if (git(root, ['ls-files', '--cached', '-z', '--', path.relative(root, target)])) throw new Error('Refusing tracked output');
    let current = root;
    for (const part of path.relative(root, target).split(path.sep)) {
        current = path.join(current, part);
        let stat;
        try { stat = fs.lstatSync(current); } catch (error) { if (error.code === 'ENOENT') continue; throw error; }
        if (stat.isSymbolicLink() || current === target || !stat.isDirectory()) throw new Error('Refusing existing output or symlink');
    }
    return target;
}
function runTests(plan, directory, timeout = 120000) {
    if (process.platform === 'win32') throw new Error('Bounded process-group runner currently supports Unix only');
    return new Promise((resolve, reject) => {
        const output = fs.openSync(path.join(directory, 'tests.tap'), 'wx', 0o600);
        const command = [process.execPath, '--require', path.join(directory, 'bootstrap.cjs'), '--test', '--test-reporter=tap',
            ...plan.test_sources.map(test => path.join(plan.root, test.path))];
        const env = { ...process.env, NODE_OPTIONS: '',
            SIGRIFT_AST_PLAN: path.join(directory, 'plan.json'), SIGRIFT_AST_PARTS: path.join(directory, 'parts') };
        // This runner is also exercised from node:test workers. Do not inherit
        // their private binary reporter/channel mode into a new test parent.
        for (const name of ['NODE_TEST_CONTEXT', 'NODE_TEST_WORKER_ID', 'NODE_CHANNEL_FD', 'NODE_CHANNEL_SERIALIZATION_MODE', 'NODE_V8_COVERAGE']) delete env[name];
        const child = spawn(command[0], command.slice(1), { cwd: plan.root, detached: true,
            stdio: ['ignore', output, output], env });
        fs.closeSync(output);
        let stopped = null;
        let killTimer;
        function kill(signal) {
            try { process.kill(-child.pid, signal); } catch (error) {
                if (!['ESRCH', 'EPERM'].includes(error.code)) throw error;
                try { child.kill(signal); } catch (inner) { if (inner.code !== 'ESRCH') throw inner; }
            }
        }
        function stop(reason) {
            if (stopped) return;
            stopped = reason; kill('SIGTERM');
            killTimer = setTimeout(() => kill('SIGKILL'), 1000);
        }
        const interrupt = () => stop('interrupted');
        process.on('SIGTERM', interrupt); process.on('SIGINT', interrupt);
        const timer = setTimeout(() => stop('timeout'), timeout);
        child.on('error', error => { cleanup(); reject(error); });
        function cleanup() {
            clearTimeout(timer); clearTimeout(killTimer);
            process.removeListener('SIGTERM', interrupt); process.removeListener('SIGINT', interrupt);
        }
        child.on('close', (status, signal) => {
            if (stopped) kill('SIGKILL'); // A descendant can outlive the direct parent.
            cleanup(); resolve({ status, signal, stopped, command: command.map(value => value.replace(plan.root, '<source>')) });
        });
    });
}
async function execute(root = ROOT, { allowDirty = false, output, reportOnly = false, timeout = 120000 } = {}) {
    root = fs.realpathSync(root);
    const target = destination(output, root);
    const plan = createPlan(root, { allowDirty });
    fs.mkdirSync(path.dirname(target), { recursive: true });
    destination(output, root);
    const directory = fs.mkdtempSync(path.join(path.dirname(target), 'node-execution-'));
    fs.chmodSync(directory, 0o700);
    fs.mkdirSync(path.join(directory, 'parts'), { mode: 0o700 });
    fs.writeFileSync(path.join(directory, 'plan.json'), JSON.stringify(plan), { flag: 'wx', mode: 0o600 });
    fs.writeFileSync(path.join(directory, 'bootstrap.cjs'), plan.programs.find(program => program.id === BOOTSTRAP).generated, { flag: 'wx', mode: 0o600 });
    let run = null; let merged = null; let error = null;
    try {
        run = await runTests(plan, directory, timeout);
        const parts = fs.readdirSync(path.join(directory, 'parts')).sort();
        if (parts.some(name => !/^[0-9]+-[0-9]+-[0-9a-f-]+\.(registration|receipt|evaluation-[0-9]+|launch-[0-9]+)\.json$/.test(name))) throw new Error('Unknown execution artifact');
        const load = suffix => parts.filter(name => typeof suffix === 'string' ? name.endsWith(suffix) : suffix.test(name)).map(name => {
            const file = path.join(directory, 'parts', name);
            if (!fs.lstatSync(file).isFile() || fs.lstatSync(file).isSymbolicLink()) throw new Error('Invalid execution artifact file');
            return JSON.parse(fs.readFileSync(file));
        });
        merged = mergeReceipts(plan, load('.registration.json'), load('.receipt.json'), load(/\.evaluation-[0-9]+\.json$/), { allowDirty, launches: load(/\.launch-[0-9]+\.json$/) });
        const tap = fs.readFileSync(path.join(directory, 'tests.tap'), 'utf8');
        const automaticFiles = new Set(plan.test_sources.flatMap(test => [test.path, path.join(plan.root, test.path)]));
        if (tap.split('\n').some(line => line.startsWith('# Subtest: ') && automaticFiles.has(line.slice(11)))) {
            throw new Error('No declared Node tests in a test driver');
        }
        const counts = {};
        for (const name of ['tests', 'pass', 'fail', 'cancelled', 'skipped', 'todo']) {
            const matches = [...tap.matchAll(new RegExp(`^# ${name} ([0-9]+)$`, 'gm'))];
            if (matches.length !== 1) throw new Error('Missing or ambiguous Node test summary');
            counts[name] = safeCount(Number(matches[0][1]));
        }
        run.tests = counts;
        if (!counts.tests || counts.pass !== counts.tests || counts.fail || counts.cancelled || counts.skipped || counts.todo
            || run.status !== 0 || run.signal || run.stopped || merged.failed_test_workers.length) throw new Error('Node tests did not all pass');
        if (!merged.contexts || !merged.observed_sources.length) throw new Error('No instrumented source execution was collected');
    } catch (failure) { error = failure.message; }
    const result = seal({ schema: 'sigrift-node-ast-result-v2', status: error ? 'invalid-or-failed-execution' : 'measured-incomplete-release-evidence',
        plan_sha256: plan.checksum, baseline_sha256: plan.baseline.manifest_sha256, source: plan.baseline.source,
        measurement: plan.baseline.measurement, producer: plan.producer, test_sources: plan.test_sources, tests_dirty: plan.tests_dirty,
        evidence_directory: path.relative(root, directory), run, error, merged,
        release_ready: false,
        limitations: ['Exact-source CommonJS/ES module loads and vm.runInContext/runInNewContext calls with explicit context objects are instrumented.',
            'Evaluation and launch journals require matching contexts, source counters and final child/worker receipts; shell launches and changed Node executable/preload configuration are unsupported.',
            'Nested independently sealed foreign-root test runs own separate evidence; other executables/runtimes and unsupported VM APIs do not gain counters from this producer.',
            'The authored bootstrap is generated offline and instrumented before launch; its uninstrumented producer pass is never retroactively credited. Finalizer counters are a snapshot, not a claim about instructions after that snapshot.',
            'Inline HTML, browser execution, unsupported runtimes and other VM APIs retain zero counts.',
            'Istanbul AST alternatives do not include every control-flow edge; this does not replace or satisfy the existing release gates.',
            'Source checks rely on trusted locked npm tooling and a trusted local producer, not cryptographic execution attestation.'] });
    destination(output, root);
    fs.writeFileSync(target, JSON.stringify(result, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
    return { result, exitCode: error || (!reportOnly && !merged.ast_counters_complete) ? 1 : 0 };
}
async function main(args = process.argv.slice(2)) {
    const outputs = args.filter(arg => arg.startsWith('--output='));
    if (outputs.length !== 1 || args.some(arg => !['--allow-dirty', '--report-only'].includes(arg) && !arg.startsWith('--output='))) {
        throw new Error('Usage: node tests/bridge/js/static_execution.cjs --output=reports/coverage/javascript-static/NEW.json [--allow-dirty] [--report-only]');
    }
    const { result, exitCode } = await execute(ROOT, { output: outputs[0].slice('--output='.length),
        allowDirty: args.includes('--allow-dirty'), reportOnly: args.includes('--report-only') });
    console.log(JSON.stringify({ status: result.status, source: result.source, tests: result.run?.tests,
        totals: result.merged?.totals, error: result.error, release_ready: false, evidence_directory: result.evidence_directory }, null, 2));
    process.exitCode = exitCode;
}
module.exports = { seal, unseal, createPlan, verifyPlan, validateCounts, snapshotCounters, identity, workerKey,
    mergeReceipts, destination, runTests, execute, main, GLOBAL, ROOT, PRELOAD, BOOTSTRAP, SELF, SELF_HASH };
if (require.main === module) main().catch(error => { console.error(error.message); process.exitCode = 1; });
