/* Source-bound Node module/VM collector installed by the authored bootstrap. */
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { randomUUID } = require('node:crypto');
const { threadId } = require('node:worker_threads');
const { hash, canonical } = require('./static_coverage.cjs');
const { seal, unseal, snapshotCounters, identity, workerKey, GLOBAL, SELF_HASH } = require('./static_execution.cjs');
const PRELOAD_HASH = hash(fs.readFileSync(__filename));

function start(planFile, partsDirectory) {
    const plan = JSON.parse(fs.readFileSync(planFile));
    unseal(plan);
    if (plan.schema !== 'sigrift-node-ast-plan-v2' || plan.producer.node !== process.version
        || plan.producer.preload_sha256 !== PRELOAD_HASH || plan.producer.execution_sha256 !== SELF_HASH) {
        throw new Error('Preload producer/plan mismatch');
    }
    const expectedParts = path.join(path.dirname(planFile), 'parts');
    if (path.resolve(partsDirectory) !== expectedParts
        || !expectedParts.startsWith(path.join(plan.root, 'reports/coverage/javascript-static') + path.sep)) throw new Error('Invalid owned evidence directory');
    let cursor = plan.root;
    for (const component of path.relative(plan.root, expectedParts).split(path.sep)) {
        cursor = path.join(cursor, component);
        const stat = fs.lstatSync(cursor);
        if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error('Unsafe evidence directory');
    }
    const candidate = process.argv[1] ? path.relative(plan.root, process.argv[1]).split(path.sep).join('/') : null;
    const driver = plan.test_sources.find(test => test.path === candidate);
    if (driver && hash(fs.readFileSync(path.join(plan.root, driver.path))) !== driver.sha256) throw new Error('Changed Node test driver');
    const launchId = process.env.SIGRIFT_AST_LAUNCH || null;
    if (launchId !== null && !/^[0-9a-f-]{36}$/.test(launchId)) throw new Error('Invalid AST launch identity');
    delete process.env.SIGRIFT_AST_LAUNCH;
    const worker = { pid: process.pid, thread_id: threadId, nonce: randomUUID(), test_path: driver?.path || null, launch_id: launchId };
    const key = workerKey(worker);
    const common = identity(plan, worker);
    function write(suffix, payload) {
        fs.writeFileSync(path.join(partsDirectory, `${key}.${suffix}.json`), JSON.stringify(seal(payload)), { flag: 'wx', mode: 0o600 });
    }
    write('registration', { schema: 'sigrift-node-ast-registration-v2', ...common });
    const records = new Map(plan.baseline.entries.map(record => [record.id, record]));
    const programs = new Map(plan.programs.map(program => [program.id, program]));
    for (const program of programs.values()) {
        const record = records.get(program.id);
        if (!record || hash(program.generated) !== record.generated_sha256) throw new Error('Generated source identity mismatch');
    }
    const contexts = new Map();
    let journalSequence = 0;
    const bootstrap = globalThis[Symbol.for('sigrift.node.ast.bootstrap.v2')];
    if (!bootstrap || bootstrap.plan_sha256 !== plan.checksum) throw new Error('Missing source-bound AST bootstrap');
    const moduleContext = { context_id: 0, context: globalThis, expected: new Map() };
    contexts.set(globalThis, moduleContext);
    bootstrap.subscribe(id => {
        const record = records.get(id);
        const evaluation = (moduleContext.expected.get(id) || 0) + 1;
        write(`evaluation-${journalSequence++}`, { schema: 'sigrift-node-ast-evaluation-v2', ...common,
            context_id: 0, id, body_sha256: record.body_sha256, generated_sha256: record.generated_sha256,
            map_sha256: record.map_sha256, evaluation });
        moduleContext.expected.set(id, evaluation);
    });
    let launchSequence = 0;
    function launched(id, kind) {
        write(`launch-${launchSequence++}`, { schema: 'sigrift-node-ast-launch-v2', ...common, launch_id: id, kind });
    }
    function childEnvironment(options, id) {
        const env = options.env === undefined ? process.env : options.env;
        if (!env || typeof env !== 'object' || env.NODE_OPTIONS) throw new Error('Unsupported measured child environment');
        return { ...env, SIGRIFT_AST_PLAN: planFile, SIGRIFT_AST_PARTS: partsDirectory, SIGRIFT_AST_LAUNCH: id };
    }
    function isNode(file, options) {
        if (file === process.execPath) return true;
        if (typeof file !== 'string') return false;
        const cwd = options?.cwd || process.cwd();
        const env = options?.env || process.env;
        // Unix child-process lookup uses /usr/bin:/bin when PATH is absent,
        // not the current directory. Require an explicit search path instead
        // of leaving a potentially different Node runtime unmeasured.
        if (file === 'node' && env.PATH === undefined) throw new Error('Named Node launch requires an explicit PATH');
        const candidates = file.includes(path.sep) ? [path.resolve(cwd, file)]
            : (env.PATH || '').split(path.delimiter).map(directory => path.resolve(cwd, directory, file));
        for (const candidate of candidates) {
            try {
                fs.accessSync(candidate, fs.constants.X_OK);
                if (fs.realpathSync(candidate) === fs.realpathSync(process.execPath)) return true;
                if (path.basename(file) === 'node') throw new Error('Node executable differs from pinned producer');
                return false;
            } catch (error) {
                if (!['ENOENT', 'ENOTDIR', 'EACCES'].includes(error.code)) throw error;
            }
        }
        return false;
    }
    const children = require('node:child_process');
    for (const method of ['spawn', 'spawnSync', 'execFile', 'execFileSync']) {
        const original = children[method];
        children[method] = function(file, ...rest) {
            if (!isNode(file, Array.isArray(rest[0]) ? rest[1] : rest[0])) return Reflect.apply(original, this, [file, ...rest]);
            if (!Array.isArray(rest[0])) rest.unshift([]);
            if (!rest[1] || typeof rest[1] !== 'object') rest.splice(1, 0, {});
            const [args, options] = rest;
            // A fixture can run another independently sealed collector rooted
            // outside this inventory. Its own plan owns that execution proof.
            if (options.env?.SIGRIFT_AST_PLAN && path.resolve(options.env.SIGRIFT_AST_PLAN) !== planFile) {
                const delegated = JSON.parse(fs.readFileSync(options.env.SIGRIFT_AST_PLAN));
                unseal(delegated);
                const expected = path.join(path.dirname(path.resolve(options.env.SIGRIFT_AST_PLAN)), 'bootstrap.cjs');
                const program = delegated.programs?.find(item => item.id === 'tests/bridge/js/static_execution_bootstrap.cjs');
                const command = ['--require', expected, '--test', '--test-reporter=tap',
                    ...(delegated.test_sources || []).map(test => path.join(delegated.root, test.path))];
                if (delegated.schema !== 'sigrift-node-ast-plan-v2' || delegated.root === plan.root
                    || delegated.producer.node !== process.version || !program
                    || canonical(args) !== canonical(command)
                    || hash(fs.readFileSync(expected)) !== hash(program.generated)) throw new Error('Unbound nested AST collector');
                return Reflect.apply(original, this, [file, ...rest]);
            }
            if (options.shell || options.env?.NODE_OPTIONS) throw new Error('Unsupported measured Node launch overrides');
            const id = randomUUID();
            rest[0] = ['--require', bootstrap.filename, ...args];
            rest[1] = { ...options, env: childEnvironment(options, id) };
            const sync = method.endsWith('Sync');
            try {
                const result = Reflect.apply(original, this, [file, ...rest]);
                if (method === 'execFileSync' || result?.pid) launched(id, 'process');
                return result;
            } catch (error) {
                // An intentional nonzero child CLI result still has valid
                // coverage when its final receipt exists and its caller passes.
                if (sync && (Number.isInteger(error.status) || error.signal)) launched(id, 'process');
                throw error;
            }
        };
    }
    const threads = require('node:worker_threads');
    const OriginalWorker = threads.Worker;
    threads.Worker = class MeasuredWorker extends OriginalWorker {
        constructor(filename, options = {}) {
            const execArgv = options.execArgv === undefined ? process.execArgv : options.execArgv;
            if (!Array.isArray(execArgv) || !execArgv.some((arg, index) => arg === '--require' && execArgv[index + 1] === bootstrap.filename)
                || options.env === threads.SHARE_ENV) throw new Error('Worker bypasses AST bootstrap');
            const id = randomUUID();
            super(filename, { ...options, env: childEnvironment(options, id) });
            launched(id, 'thread');
        }
    };
    const originalFork = children.fork;
    children.fork = function(modulePath, args, options) {
        if (!Array.isArray(args)) { options = args; args = []; }
        options ||= {};
        if (options.execPath !== undefined && fs.realpathSync(options.execPath) !== fs.realpathSync(process.execPath)) {
            throw new Error('Fork Node executable differs from pinned producer');
        }
        const execArgv = options.execArgv === undefined ? process.execArgv : options.execArgv;
        if (!Array.isArray(execArgv) || !execArgv.some((arg, index) => arg === '--require' && execArgv[index + 1] === bootstrap.filename)) {
            throw new Error('Fork bypasses AST bootstrap');
        }
        const id = randomUUID();
        const result = Reflect.apply(originalFork, this, [modulePath, args, { ...options, env: childEnvironment(options, id) }]);
        if (result.pid) launched(id, 'process');
        return result;
    };
    require('node:module').syncBuiltinESMExports();
    const originals = { runInContext: vm.runInContext, runInNewContext: vm.runInNewContext };
    for (const method of Object.keys(originals)) {
        vm[method] = function(code, context, options) {
            const filename = typeof options === 'string' ? options : options?.filename;
            const relative = typeof filename === 'string' && path.isAbsolute(filename)
                ? path.relative(plan.root, filename).split(path.sep).join('/') : null;
            const program = programs.get(relative);
            // Unadapted calls retain their actual behavior and zero AST counts.
            if (!program || !context || typeof context !== 'object') return Reflect.apply(originals[method], this, arguments);
            const record = records.get(relative);
            if (typeof code !== 'string' || hash(code) !== record.body_sha256
                || hash(fs.readFileSync(filename)) !== record.body_sha256) throw new Error('Executed source differs from baseline');
            let entry = contexts.get(context);
            if (!entry) {
                if (GLOBAL in context) throw new Error('Preexisting context counters cannot establish execution');
                entry = { context_id: contexts.size, context, expected: new Map() };
                contexts.set(context, entry);
            }
            const evaluation = (entry.expected.get(relative) || 0) + 1;
            write(`evaluation-${journalSequence++}`, { schema: 'sigrift-node-ast-evaluation-v2', ...common,
                context_id: entry.context_id, id: relative, body_sha256: record.body_sha256,
                generated_sha256: record.generated_sha256, map_sha256: record.map_sha256, evaluation });
            entry.expected.set(relative, evaluation);
            return Reflect.apply(originals[method], this, [program.generated, context, options]);
        };
    }
    // Exit listeners may execute covered code too. Snapshot after synchronous
    // exit dispatch, not in a preload-registered listener that would run first.
    // Keeping each context alive is intentional: snapshot once, not once per
    // evaluation, so callbacks and shared-context loads are neither lost nor doubled.
    let finalized = false;
    function finalize(code) {
        if (finalized) {
            // A manually emitted early exit cannot masquerade as a final sample.
            write('duplicate-exit', { error: 'Multiple exit dispatches' });
            process.exitCode = 1;
            return;
        }
        finalized = true;
        const snapshots = [];
        const counterObjects = new Set();
        let error = null;
        try {
            for (const entry of contexts.values()) {
                const values = entry.context[GLOBAL];
                if (!values || canonical(Object.keys(values).sort()) !== canonical([...entry.expected.keys()].sort())) {
                    throw new Error('Missing or unknown context counters');
                }
                if (counterObjects.has(values)) throw new Error('Shared context counters cannot be counted twice');
                counterObjects.add(values);
                const entries = [...entry.expected].map(([id, evaluations]) => {
                    const record = records.get(id);
                    if (counterObjects.has(values[id])) throw new Error('Shared source counters cannot be counted twice');
                    counterObjects.add(values[id]);
                    return { id, body_sha256: record.body_sha256, generated_sha256: record.generated_sha256,
                        map_sha256: record.map_sha256, evaluations,
                        counts: snapshotCounters(values[id], record, programs.get(id)) };
                });
                snapshots.push({ context_id: entry.context_id, entries });
            }
        } catch (failure) { error = failure.message; process.exitCode = 1; }
        try {
            write('receipt', { schema: 'sigrift-node-ast-receipt-v2', ...common,
                exit_code: process.exitCode || code || 0, contexts: snapshots, error });
        } catch (_) { process.exitCode = 1; process.stderr.write('AST collector could not write its final receipt.\n'); }
    }
    const emit = process.emit;
    process.emit = function(event, ...args) {
        if (event !== 'exit') return Reflect.apply(emit, this, [event, ...args]);
        try { return Reflect.apply(emit, this, [event, ...args]); }
        finally { finalize(args[0]); }
    };
}
if (process.env.SIGRIFT_AST_PLAN || process.env.SIGRIFT_AST_PARTS) {
    if (!process.env.SIGRIFT_AST_PLAN || !process.env.SIGRIFT_AST_PARTS) throw new Error('Incomplete AST execution configuration');
    start(path.resolve(process.env.SIGRIFT_AST_PLAN), path.resolve(process.env.SIGRIFT_AST_PARTS));
}
module.exports = { start };
