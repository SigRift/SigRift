const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const vm = require('node:vm');
const { randomUUID } = require('node:crypto');
const { execFileSync } = require('node:child_process');
const test = require('node:test');
const { hash, canonical } = require('./static_coverage.cjs');
const { createPlan, verifyPlan, seal, snapshotCounters, identity, mergeReceipts, execute,
    destination, GLOBAL } = require('./static_execution.cjs');
const clone = value => JSON.parse(JSON.stringify(value));
const DRIVER = 'tests/bridge/js/probe.test.cjs';

function fixture(t, files = {}) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sigrift-node-ast-'));
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    const write = (name, source) => {
        const target = path.join(root, name); fs.mkdirSync(path.dirname(target), { recursive: true }); fs.writeFileSync(target, source);
    };
    for (const name of ['inventory.py', 'static_coverage.cjs', 'static_execution.cjs', 'static_execution_preload.cjs', 'static_execution_bootstrap.cjs', 'package.json', 'package-lock.json']) {
        write(`tests/bridge/js/${name}`, fs.readFileSync(path.join(__dirname, name)));
    }
    write('.gitignore', 'node_modules/\nreports/\n');
    write('src/probe.js', 'globalThis.choose = flag => flag ? 11 : 22;\n');
    write('src/unloaded.js', 'function dormant(flag) { if (flag) return 1; return 2; }\n');
    write('src/page.html', '<!doctype html><script>if (ready) go()</script><button onclick="return event.ok">Go</button>');
    write(DRIVER, `const test = require('node:test'); test('placeholder', () => {});`);
    for (const [name, source] of Object.entries(files)) write(name, source);
    fs.symlinkSync(path.join(__dirname, 'node_modules'), path.join(root, 'tests/bridge/js/node_modules'), 'dir');
    const git = (...args) => execFileSync('git', ['-c', 'user.name=Coverage fixture', '-c', 'user.email=coverage@example.invalid',
        '-c', 'commit.gpgsign=false', ...args], { cwd: root, stdio: 'pipe' });
    git('init', '-q'); git('add', '.'); git('commit', '-qm', 'AST execution fixture');
    return { root, write, git };
}
function actualEvidence(plan, choose = true, overrides = {}) {
    const record = plan.baseline.entries.find(entry => entry.id === 'src/probe.js');
    const program = plan.programs.find(entry => entry.id === record.id);
    const context = vm.createContext({}, { codeGeneration: { strings: false, wasm: false } });
    vm.runInContext(program.generated, context);
    assert.equal(context.choose(choose), choose ? 11 : 22);
    const counts = snapshotCounters(context[GLOBAL][record.id], record, program);
    const worker = { pid: process.pid, thread_id: 0, nonce: randomUUID(), test_path: DRIVER, ...overrides };
    const common = identity(plan, worker);
    const registration = seal({ schema: 'sigrift-node-ast-registration-v2', ...common });
    const receipt = seal({ schema: 'sigrift-node-ast-receipt-v2', ...common, exit_code: 0, error: null,
        contexts: [{ context_id: 0, entries: [{ id: record.id, body_sha256: record.body_sha256,
            generated_sha256: record.generated_sha256, map_sha256: record.map_sha256, evaluations: 1, counts }] }] });
    const evaluation = seal({ schema: 'sigrift-node-ast-evaluation-v2', ...common, context_id: 0,
        id: record.id, body_sha256: record.body_sha256, generated_sha256: record.generated_sha256,
        map_sha256: record.map_sha256, evaluation: 1 });
    return { registration, receipt, evaluation, record, program, context };
}
function reseal(value) { delete value.checksum; return seal(value); }

const driver = body => `
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const root = path.resolve(__dirname, '../../..');
const filename = path.join(root, 'src/probe.js');
const source = fs.readFileSync(filename, 'utf8');
${body}
`;

test('real AST counters merge compatible executions while unloaded/inline/helpers remain zero', t => {
    const f = fixture(t); const plan = createPlan(f.root);
    const a = actualEvidence(plan, true); const b = actualEvidence(plan, false);
    const result = mergeReceipts(plan, [a.registration, b.registration], [a.receipt, b.receipt], [a.evaluation, b.evaluation]);
    assert.deepEqual(Object.values(result.coverage['src/probe.js'].b)[0], [1, 1]);
    assert.deepEqual(result.observed_sources, ['src/probe.js']);
    assert.equal(result.ast_counters_complete, false);
    for (const [name, coverage] of Object.entries(result.coverage)) if (name !== 'src/probe.js') {
        assert.ok(Object.values(coverage.s).every(count => count === 0), name);
        assert.ok(Object.values(coverage.f).every(count => count === 0), name);
        assert.ok(Object.values(coverage.b).flat().every(count => count === 0), name);
    }
    assert.ok(result.unobserved_sources.includes('tests/bridge/js/static_execution.cjs'));
    assert.equal(plan.baseline.inventory.inline_behaviors, 2);
    assert.equal(Object.keys(result.coverage).length, plan.baseline.entries.length);
});

test('strict importer rejects missing/unknown/negative/fractional/overflowed real counter shapes', t => {
    const f = fixture(t); const plan = createPlan(f.root); const e = actualEvidence(plan);
    const changes = [
        entry => { delete entry.counts.s[Object.keys(entry.counts.s)[0]]; },
        entry => { entry.counts.s.unknown = 1; },
        entry => { entry.counts.extra = {}; },
        entry => { entry.counts.f[Object.keys(entry.counts.f)[0]] = -1; },
        entry => { entry.counts.f[Object.keys(entry.counts.f)[0]] = 1.5; },
        entry => { entry.counts.f[Object.keys(entry.counts.f)[0]] = Number.MAX_SAFE_INTEGER + 1; },
        entry => { entry.counts.f[Object.keys(entry.counts.f)[0]] = '1'; },
        entry => { entry.counts.f[Object.keys(entry.counts.f)[0]] = null; },
        entry => { entry.counts.b[Object.keys(entry.counts.b)[0]].pop(); },
        entry => { entry.counts.b[Object.keys(entry.counts.b)[0]].push(0); },
        entry => { entry.counts.b[Object.keys(entry.counts.b)[0]][0] = -2; },
        entry => { entry.id = 'src/unknown.js'; },
        entry => { entry.body_sha256 = 'wrong'; },
        entry => { entry.generated_sha256 = 'wrong'; },
        entry => { entry.map_sha256 = 'wrong'; },
        entry => { entry.evaluations = 0; },
    ];
    for (const change of changes) {
        const bad = clone(e.receipt); change(bad.contexts[0].entries[0]);
        assert.throws(() => mergeReceipts(plan, [e.registration], [reseal(bad)], [e.evaluation]));
    }
    const raw = clone(e.context[GLOBAL][e.record.id]);
    raw.statementMap[Object.keys(raw.statementMap)[0]].start.line++;
    assert.throws(() => snapshotCounters(raw, e.record, e.program), /map\/source mismatch/);
    raw.statementMap = e.record.coverage.statementMap; raw.hash = 'wrong';
    assert.throws(() => snapshotCounters(raw, e.record, e.program), /runtime hash/);
    const bad = clone(e.receipt); bad.contexts[0].entries[0].counts.s['0']++;
    assert.throws(() => mergeReceipts(plan, [e.registration], [bad], [e.evaluation]), /checksum/);
});

test('merge rejects overflow, duplicate/missing receipts and incompatible source/tool provenance', t => {
    const f = fixture(t); const plan = createPlan(f.root); const a = actualEvidence(plan); const b = actualEvidence(plan);
    const overflow = clone(a.receipt); overflow.contexts[0].entries[0].counts.s['0'] = Number.MAX_SAFE_INTEGER;
    assert.throws(() => mergeReceipts(plan, [a.registration, b.registration], [reseal(overflow), b.receipt], [a.evaluation, b.evaluation]), /overflow/);
    assert.throws(() => mergeReceipts(plan, [a.registration], [a.receipt, a.receipt], [a.evaluation]), /duplicate/);
    assert.throws(() => mergeReceipts(plan, [a.registration, b.registration], [a.receipt], [a.evaluation, b.evaluation]), /Missing final/);
    assert.throws(() => mergeReceipts(plan, [], [], []), /Missing registered/);
    for (const key of ['run_id', 'baseline_sha256', 'plan_sha256']) {
        const bad = clone(a.receipt); bad[key] = 'wrong';
        assert.throws(() => mergeReceipts(plan, [a.registration], [reseal(bad)], [a.evaluation]), /Incompatible/);
    }
    const bad = clone(a.receipt); bad.producer.node = 'v0.0.0';
    assert.throws(() => mergeReceipts(plan, [a.registration], [reseal(bad)], [a.evaluation]), /Incompatible/);
});

test('evaluation journal rejects dropped contexts/sources and unknown/missing/duplicate evaluations', t => {
    const f = fixture(t); const plan = createPlan(f.root); const e = actualEvidence(plan);
    const missing = clone(e.receipt); missing.contexts = [];
    assert.throws(() => mergeReceipts(plan, [e.registration], [reseal(missing)], [e.evaluation]), /Missing context/);
    const noSource = clone(e.receipt); noSource.contexts[0].entries = [];
    assert.throws(() => mergeReceipts(plan, [e.registration], [reseal(noSource)], [e.evaluation]), /Invalid context/);
    assert.throws(() => mergeReceipts(plan, [e.registration], [e.receipt], []), /Unknown context/);
    assert.throws(() => mergeReceipts(plan, [e.registration], [e.receipt], [e.evaluation, e.evaluation]), /Duplicate evaluation/);
    for (const [field, value] of [['id', 'missing.js'], ['body_sha256', 'wrong'], ['generated_sha256', 'wrong'],
        ['map_sha256', 'wrong'], ['context_id', -1], ['evaluation', 0], ['evaluation', 1.5]]) {
        const bad = clone(e.evaluation); bad[field] = value;
        assert.throws(() => mergeReceipts(plan, [e.registration], [e.receipt], [reseal(bad)]), /Invalid evaluation/);
    }
    const gap = clone(e.evaluation); gap.evaluation = 2;
    assert.throws(() => mergeReceipts(plan, [e.registration], [e.receipt], [reseal(gap)]), /Missing evaluation/);
    assert.throws(() => mergeReceipts(plan, [e.registration], [e.receipt], [e.evaluation, reseal(gap)]), /differs from evaluation/);
});

test('import reconstructs source/maps and rejects replaced source, generated code and test drivers', t => {
    const f = fixture(t); const plan = createPlan(f.root); const e = actualEvidence(plan);
    const tampered = clone(plan); tampered.programs[0].generated += '\n// altered';
    assert.throws(() => verifyPlan(reseal(tampered), f.root), /differs/);
    const original = fs.readFileSync(path.join(f.root, 'src/probe.js'));
    f.write('src/probe.js', original + '\n// changed');
    assert.throws(() => mergeReceipts(plan, [e.registration], [e.receipt], [e.evaluation]), /Dirty/);
    f.write('src/probe.js', original);
    f.write(DRIVER, fs.readFileSync(path.join(f.root, DRIVER)) + '\n// changed test');
    // Test drivers are now source-bound by the baseline before receipt import.
    assert.throws(() => mergeReceipts(plan, [e.registration], [e.receipt], [e.evaluation]), /Dirty JavaScript measurement inputs/);
});

test('deleted tracked test drivers fail by default and remain explicit in dirty development plans', t => {
    const other = 'tests/bridge/js/other.test.cjs';
    const f = fixture(t, { [other]: "require('node:test')('second actual test',()=>{});" });
    const clean = createPlan(f.root);
    assert.equal(clean.tests_dirty, false);
    assert.equal(clean.test_sources.length, 2);
    f.git('rm', other); // Removed from the index too; still a driver at HEAD.
    assert.throws(() => createPlan(f.root), /Dirty JavaScript measurement inputs/);
    const dirty = createPlan(f.root, { allowDirty: true });
    assert.equal(dirty.tests_dirty, true);
    assert.deepEqual(dirty.test_sources.map(test => test.path), [DRIVER]);
    assert.throws(() => verifyPlan(clean, f.root, { allowDirty: true }), /differs/);
});

test('real Node test workers collect delayed callbacks, repeated contexts and inherited Worker threads', async t => {
    const f = fixture(t, { [DRIVER]: driver(`
const { Worker } = require('node:worker_threads');
test('callbacks and shared contexts', async () => {
    const context = vm.createContext({}, { codeGeneration: { strings: false, wasm: false } });
    vm.runInContext(source, context, { filename });
    assert.equal(context.choose(true), 11);
    await new Promise(resolve => setTimeout(() => { assert.equal(context.choose(false), 22); resolve(); }, 15));
    vm.runInContext(source, context, { filename });
    assert.equal(context.choose(true), 11);
    process.on('exit', () => context.choose(false));
});
test('worker receives the same preload and exits after async work', async () => {
    const code = "const {workerData}=require('node:worker_threads'); const vm=require('node:vm'); const fs=require('node:fs'); const c={}; vm.runInNewContext(fs.readFileSync(workerData,'utf8'),c,{filename:workerData}); setTimeout(()=>c.choose(false),15);";
    const worker = new Worker(code, { eval: true, workerData: filename });
    await new Promise((resolve,reject) => { worker.on('error',reject); worker.on('exit', code => code ? reject(new Error('worker failed')) : resolve()); });
});`) });
    const { result, exitCode } = await execute(f.root, { output: 'reports/coverage/javascript-static/run.json', reportOnly: true });
    assert.equal(exitCode, 0, result.error);
    assert.equal(result.run.tests.tests, 2);
    assert.ok(result.merged.workers >= 3);
    assert.equal(result.merged.contexts, result.merged.workers + 2);
    assert.deepEqual(Object.values(result.merged.coverage['src/probe.js'].b)[0], [2, 3]);
    assert.equal(result.release_ready, false);
    assert.equal(result.merged.ast_counters_complete, false);
});

for (const [name, code, expected] of [
    ['failed assertion', `test('fails after executing', () => { const c={}; vm.runInNewContext(source,c,{filename}); c.choose(true); assert.fail('intentional fixture failure'); });`, /Node tests/],
    ['skipped test', `test.skip('not executed', () => {});`, /Node tests/],
    ['no test cases', `// intentionally empty test driver`, /No declared Node tests/],
    ['abrupt worker exit', `test('lost receipt', () => { process.kill(process.pid,'SIGKILL'); });`, /Missing final/],
    ['missing counters', `test('missing counters', () => { const c={}; vm.runInNewContext(source,c,{filename}); delete c.__sigrift_static_coverage__; });`, /Collector reported/],
    ['inherited context counters', `test('prototype counters cannot be shared', () => {
        const first={}; vm.runInNewContext(source,first,{filename}); assert.equal(first.choose(true),11);
        const second=Object.create(first); vm.runInNewContext(source,second,{filename}); second.choose(false);
    });`, /Node tests/],
    ...['global', 'source'].map(kind => [`aliased ${kind} counters`, `test('shared final counters', () => {
        const first={}; vm.runInNewContext(source,first,{filename}); first.choose(true);
        const second={}; vm.runInNewContext(source,second,{filename}); second.choose(false);
        ${kind === 'global' ? 'second.__sigrift_static_coverage__=first.__sigrift_static_coverage__;' : "second.__sigrift_static_coverage__['src/probe.js']=first.__sigrift_static_coverage__['src/probe.js'];"}
    });`, /Collector reported/]),
    ['terminated thread', `test('thread killed before final receipt', async () => {
        const {Worker}=require('node:worker_threads');
        const worker=new Worker("const {parentPort,workerData}=require('node:worker_threads'); const vm=require('node:vm'); const fs=require('node:fs'); const c={}; vm.runInNewContext(fs.readFileSync(workerData,'utf8'),c,{filename:workerData}); c.choose(true); parentPort.postMessage('ready'); setInterval(()=>{},1000);", {eval:true,workerData:filename});
        await new Promise((resolve,reject)=>{worker.once('message',resolve); worker.once('error',reject);});
        await worker.terminate();
    });`, /Missing final/],
    ['early manual exit dispatch', `test('false final sample', () => { const c={}; vm.runInNewContext(source,c,{filename}); process.emit('exit',0); c.choose(true); });`, /Unknown execution artifact/],
    ['source mismatch at VM call', `test('changed executed bytes', () => { vm.runInNewContext(source+'\\n// changed',{}, {filename}); });`, /Node tests/],
]) {
    test(`${name} remains a failure with its partial artifacts preserved`, async t => {
        const f = fixture(t, { [DRIVER]: driver(code) });
        const { result, exitCode } = await execute(f.root, { output: 'reports/coverage/javascript-static/run.json', reportOnly: true });
        assert.equal(exitCode, 1);
        assert.match(result.error, expected);
        assert.equal(result.release_ready, false);
        const directory = path.join(f.root, result.evidence_directory);
        assert.ok(fs.existsSync(path.join(directory, 'tests.tap')));
        assert.ok(fs.existsSync(path.join(directory, 'plan.json')));
        assert.ok(fs.readdirSync(path.join(directory, 'parts')).length);
        if (name === 'failed assertion') {
            assert.ok(result.merged.totals.lines.covered > 0);
            assert.ok(result.merged.failed_workers.length);
        }
    });
}

test('unadapted VM APIs execute normally but cannot claim AST coverage', async t => {
    const f = fixture(t, { [DRIVER]: driver(`test('mixed API coverage', () => {
        const c={}; vm.runInNewContext(source,c,{filename}); assert.equal(c.choose(true),11);
        const other=path.join(root,'src/unloaded.js'); const context=vm.createContext({});
        new vm.Script(fs.readFileSync(other,'utf8'),{filename:other}).runInContext(context);
        assert.equal(context.dormant(true),1);
    });`) });
    const { result, exitCode } = await execute(f.root, { output:'reports/coverage/javascript-static/run.json', reportOnly:true });
    assert.equal(exitCode,0,result.error);
    assert.ok(result.merged.observed_sources.includes('src/probe.js'));
    assert.ok(!result.merged.observed_sources.includes('src/unloaded.js'));
    for (const id of ['static_execution_bootstrap.cjs','static_execution_preload.cjs','static_execution.cjs','static_coverage.cjs']) {
        assert.ok(result.merged.observed_sources.includes('tests/bridge/js/'+id));
    }
    assert.ok(Object.values(result.merged.coverage['src/unloaded.js'].s).every(value=>value===0));
});

test('uncovered AST alternatives cause a nonzero default result after passing real tests', async t => {
    const f = fixture(t, { [DRIVER]: driver(`test('one branch',()=>{ const c={}; vm.runInNewContext(source,c,{filename}); assert.equal(c.choose(true),11); });`) });
    const { result, exitCode } = await execute(f.root, { output: 'reports/coverage/javascript-static/run.json' });
    assert.equal(result.error, null); assert.equal(result.run.tests.pass, 1);
    assert.equal(exitCode, 1); assert.equal(result.merged.ast_counters_complete, false);
});

test('bounded runner terminates stuck workers and preserves failure evidence', async t => {
    const f = fixture(t, { [DRIVER]: driver(`test('stuck', () => new Promise(()=>{setInterval(()=>{},1000);}));`) });
    const { result, exitCode } = await execute(f.root, { output: 'reports/coverage/javascript-static/run.json', reportOnly: true, timeout: 500 });
    assert.equal(exitCode, 1); assert.equal(result.run.stopped, 'timeout');
    assert.equal(result.release_ready, false);
});

test('new execution outputs cannot replace authored/tracked/hardlink/symlink files', t => {
    const f = fixture(t); const file = path.join(f.root, 'src/probe.js'); const before = fs.readFileSync(file);
    assert.throws(() => destination('src/probe.js', f.root), /new JSON/);
    fs.mkdirSync(path.join(f.root, 'reports/coverage/javascript-static'), { recursive: true });
    fs.linkSync(file, path.join(f.root, 'reports/coverage/javascript-static/hard.json'));
    assert.throws(() => destination('reports/coverage/javascript-static/hard.json', f.root), /existing/);
    fs.symlinkSync(path.join(f.root, 'src'), path.join(f.root, 'reports/coverage/javascript-static/alias'));
    assert.throws(() => destination('reports/coverage/javascript-static/alias/new.json', f.root), /symlink/);
    fs.writeFileSync(path.join(f.root, 'reports/coverage/javascript-static/tracked.json'), '{}');
    f.git('add', '-f', 'reports/coverage/javascript-static/tracked.json');
    fs.unlinkSync(path.join(f.root, 'reports/coverage/javascript-static/tracked.json'));
    assert.throws(() => destination('reports/coverage/javascript-static/tracked.json', f.root), /tracked/);
    assert.deepEqual(fs.readFileSync(file), before);
});

test('real CommonJS and ES module loads preserve identity and record delayed module branches', async t => {
    const f = fixture(t, {
        'src/module.cjs': "module.exports = flag => ({ value:flag?17:29, filename:__filename, dirname:__dirname, main:require.main===module });\n",
        'src/module.mjs': "export const identity=import.meta.url; export function choose(flag){return flag?31:43;}\n",
        [DRIVER]: driver(`test('actual module graph',async()=>{
            const cjs=require(path.join(root,'src/module.cjs'));
            assert.equal(cjs(true).value,17); assert.equal(cjs(false).value,29);
            assert.equal(cjs(true).filename,path.join(root,'src/module.cjs'));
            assert.equal(cjs(true).dirname,path.join(root,'src')); assert.equal(cjs(true).main,false);
            const esm=await import(require('node:url').pathToFileURL(path.join(root,'src/module.mjs')).href);
            assert.equal(esm.identity,require('node:url').pathToFileURL(path.join(root,'src/module.mjs')).href);
            assert.equal(esm.choose(true),31);await new Promise(resolve=>setTimeout(()=>{assert.equal(esm.choose(false),43);resolve()},10));
        });`),
    });
    const {result,exitCode}=await execute(f.root,{output:'reports/coverage/javascript-static/modules.json',reportOnly:true});
    assert.equal(exitCode,0,result.error);
    for(const id of ['src/module.cjs','src/module.mjs',DRIVER]) assert.ok(result.merged.observed_sources.includes(id),id);
    for(const id of ['src/module.cjs','src/module.mjs']) assert.ok(Object.values(result.merged.coverage[id].b).flat().every(n=>n>0),id);
});

test('an explicit Worker preload bypass cannot produce successful coverage', async t => {
    const f=fixture(t,{[DRIVER]:driver(`test('bypassed thread',async()=>{
        const c={};vm.runInNewContext(source,c,{filename});c.choose(true);
        const {Worker}=require('node:worker_threads');
        const w=new Worker("require('node:fs').readFileSync",{eval:true,execArgv:[]});
        await new Promise((resolve,reject)=>{w.once('error',reject);w.once('exit',resolve)});
    });`)});
    const {result,exitCode}=await execute(f.root,{output:'reports/coverage/javascript-static/bypass.json',reportOnly:true});
    assert.equal(exitCode,1);assert.equal(result.release_ready,false);
});

test('an owned Node child module has a source-bound final receipt', async t => {
    const f=fixture(t,{'src/child.cjs':"if(require.main!==module)throw Error('wrong main identity');if(process.argv[2]!=='expected')throw Error('wrong arguments');\n",
        [DRIVER]:driver(`test('actual child',()=>{
            const c={};vm.runInNewContext(source,c,{filename});c.choose(true);
            require('node:child_process').execFileSync(process.execPath,[path.join(root,'src/child.cjs'),'expected']);
        });`)});
    const {result,exitCode}=await execute(f.root,{output:'reports/coverage/javascript-static/child.json',reportOnly:true});
    assert.equal(exitCode,0,result.error);
    assert.ok(result.merged.observed_sources.includes('src/child.cjs'));
});

test('sync, async, PATH-resolved and forked Node children retain arguments and complete receipts', async t => {
    const f=fixture(t,{
        'src/child.cjs':"const assert=require('node:assert/strict');assert.equal(require.main,module);assert.equal(process.argv[2],'expected');if(process.send)process.send('ready');else process.stdout.write('ready');\n",
        [DRIVER]:driver(`test('all child APIs',async()=>{
            const cp=require('node:child_process');const child=path.join(root,'src/child.cjs');
            assert.equal(cp.execFileSync(process.execPath,[child,'expected'],{env:{},encoding:'utf8'}),'ready');
            const sync=cp.spawnSync('node',[child,'expected'],{env:{PATH:path.dirname(process.execPath)},encoding:'utf8'});
            assert.equal(sync.status,0);assert.equal(sync.stdout,'ready');
            await new Promise((resolve,reject)=>cp.execFile(process.execPath,[child,'expected'],(error,stdout)=>{if(error)reject(error);else{assert.equal(stdout,'ready');resolve()}}));
            const spawned=cp.spawn(process.execPath,[child,'expected'],{stdio:'pipe'});
            await new Promise((resolve,reject)=>{spawned.once('error',reject);spawned.once('exit',code=>code?reject(Error('spawn failed')):resolve())});
            const fork=cp.fork(child,['expected'],{silent:true,execPath:process.execPath});let message;
            fork.once('message',value=>message=value);
            await new Promise((resolve,reject)=>{fork.once('error',reject);fork.once('exit',code=>code?reject(Error('fork failed')):resolve())});
            assert.equal(message,'ready');
        });`)});
    const {result,exitCode}=await execute(f.root,{output:'reports/coverage/javascript-static/child-apis.json',reportOnly:true});
    assert.equal(exitCode,0,result.error);assert.equal(result.merged.launched_workers,5);
    assert.ok(result.merged.observed_sources.includes('src/child.cjs'));
});

test('an intentional failing child remains measured when the real test asserts its outcome', async t => {
    const f=fixture(t,{'src/refusal.cjs':"process.exitCode=7;\n",[DRIVER]:driver(`test('expected CLI refusal',()=>{
        assert.throws(()=>require('node:child_process').execFileSync(process.execPath,[path.join(root,'src/refusal.cjs')]),error=>error.status===7);
    });`)});
    const {result,exitCode}=await execute(f.root,{output:'reports/coverage/javascript-static/expected-refusal.json',reportOnly:true});
    assert.equal(exitCode,0,result.error);assert.equal(result.merged.failed_workers.length,1);
    assert.equal(result.merged.failed_test_workers.length,0);
    assert.ok(Object.values(result.merged.coverage['src/refusal.cjs'].s).every(value=>value>0));
});

test('a killed child loses its final receipt even when its parent expects the signal', async t => {
    const f=fixture(t,{'src/killed.cjs':"process.kill(process.pid,'SIGKILL');\n",[DRIVER]:driver(`test('actual killed CLI',()=>{
        assert.throws(()=>require('node:child_process').execFileSync(process.execPath,[path.join(root,'src/killed.cjs')]),error=>error.signal==='SIGKILL');
    });`)});
    const {result,exitCode}=await execute(f.root,{output:'reports/coverage/javascript-static/killed-child.json',reportOnly:true});
    assert.equal(exitCode,1);assert.match(result.error,/Missing final worker receipt/);
});

test('later module loaders and unsupported Node environment overrides are refused before execution', async t => {
    const f=fixture(t,{[DRIVER]:driver(`test('loader and launch refusal',()=>{
        const modules=require('node:module');
        assert.throws(()=>modules.registerHooks({load(){throw Error('should not execute')}}),/not source-bound/);
        assert.throws(()=>modules.register('data:text/javascript,export function load(){}'),/not source-bound/);
        const cp=require('node:child_process');
        assert.throws(()=>cp.execFileSync(process.execPath,['-e','throw Error("should not execute")'],{env:{NODE_OPTIONS:'--inspect=0'}}),/overrides/);
        assert.throws(()=>cp.fork(filename,[],{execArgv:[]}),/bypasses/);
    });`)});
    const {result,exitCode}=await execute(f.root,{output:'reports/coverage/javascript-static/refused-loaders.json',reportOnly:true});
    assert.equal(exitCode,0,result.error);assert.equal(result.merged.launched_workers,0);
});

test('module cache reuse counts real function calls without inventing repeated module evaluation', async t => {
    const f=fixture(t,{'src/cached.cjs':"module.exports=flag=>flag?3:5;\n",[DRIVER]:driver(`test('require cache',()=>{
        const a=require(path.join(root,'src/cached.cjs'));const b=require(path.join(root,'src/cached.cjs'));
        assert.equal(a,b);assert.equal(a(true),3);assert.equal(b(false),5);assert.equal(a(true),3);
    });`)});
    const {result,exitCode}=await execute(f.root,{output:'reports/coverage/javascript-static/cache.json',reportOnly:true});
    assert.equal(exitCode,0,result.error);
    assert.deepEqual(Object.values(result.merged.coverage['src/cached.cjs'].b)[0],[2,1]);
    const directory=path.join(f.root,result.evidence_directory,'parts');
    const events=fs.readdirSync(directory).filter(name=>name.includes('.evaluation-')).map(name=>JSON.parse(fs.readFileSync(path.join(directory,name))));
    assert.equal(events.filter(event=>event.id==='src/cached.cjs').length,1);
});

test('registered child launch identities cannot be dropped, reused or rebound', t => {
    const f=fixture(t);const plan=createPlan(f.root);const parent=actualEvidence(plan);
    const launchId=randomUUID();const child=actualEvidence(plan,false,{pid:process.pid+1,launch_id:launchId,test_path:null});
    const launch=seal({schema:'sigrift-node-ast-launch-v2',...identity(plan,parent.registration.worker),launch_id:launchId,kind:'process'});
    const run=launches=>mergeReceipts(plan,[parent.registration,child.registration],[parent.receipt,child.receipt],[parent.evaluation,child.evaluation],{launches});
    assert.equal(run([launch]).launched_workers,1);
    assert.throws(()=>run([]),/Unbound child/);
    assert.throws(()=>run([launch,launch]),/duplicate child launch/);
    const bad=clone(launch);bad.kind='thread';assert.throws(()=>run([reseal(bad)]),/Unbound child/);
    for (const changed of [{test_path:null}, {launch_id:randomUUID()}]) {
        const forged=clone(launch);Object.assign(forged.worker,changed);
        assert.throws(()=>run([reseal(forged)]),/Invalid or duplicate child launch/);
    }
    assert.throws(()=>mergeReceipts(plan,[parent.registration],[parent.receipt],[parent.evaluation],{launches:[launch]}),/Missing launched/);
});

for (const mode of ['PATH-less named Node', 'fork executable override']) test(`${mode} refuses before execution`, async t => {
    const f=fixture(t,{'tools/other-node':'#!/bin/sh\ntouch "$(dirname "$0")/executed"\n',
        [DRIVER]:driver(`test('unsupported executable selection',async()=>{
            const cp=require('node:child_process');
            if (${JSON.stringify(mode)}==='PATH-less named Node') {
                assert.throws(()=>cp.spawnSync('node',['-e','process.exit(0)'],{env:{}}),/requires an explicit PATH/);
            } else {
            const alternate=path.join(root,'tools/other-node');fs.chmodSync(alternate,0o700);
            let child;
            try {assert.throws(()=>{child=cp.fork(path.join(root,'src/choice.js'),[],{execPath:alternate,silent:true})},/differs from pinned producer/);}
            finally {if(child)await new Promise(resolve=>child.once('exit',resolve));}
            assert.equal(fs.existsSync(path.join(root,'tools/executed')),false);
            }
            assert.equal(cp.execFileSync(process.execPath,['-e','process.stdout.write("pinned")'],{env:{},encoding:'utf8'}),'pinned');
        });`)});
    const {result,exitCode}=await execute(f.root,{output:'reports/coverage/javascript-static/executable-policy.json',reportOnly:true});
    assert.equal(exitCode,0,result.error);
    assert.equal(result.merged.launched_workers,1);
});

test('a changed module is refused before its body executes even if disk bytes are restored', async t => {
    const f=fixture(t,{'src/changed.cjs':"globalThis.changedModuleExecuted=true;module.exports=9;\n",[DRIVER]:driver(`test('changed bytes at actual load',()=>{
        const target=path.join(root,'src/changed.cjs');const before=fs.readFileSync(target);
        try{fs.writeFileSync(target,Buffer.concat([before,Buffer.from('// unexpected bytes')]));
            assert.throws(()=>require(target),/differs from source-bound plan/);
            assert.equal(globalThis.changedModuleExecuted,undefined);
        }finally{fs.writeFileSync(target,before);}
    });`)});
    const {result,exitCode}=await execute(f.root,{output:'reports/coverage/javascript-static/changed-load.json',reportOnly:true});
    assert.equal(exitCode,0,result.error);
    assert.ok(!result.merged.observed_sources.includes('src/changed.cjs'));
    assert.ok(Object.values(result.merged.coverage['src/changed.cjs'].s).every(n=>n===0));
});

test('ES module Worker entrypoints inherit the hook and merge distinct real branches', async t => {
    const f=fixture(t,{'src/worker-choice.mjs':"export default flag=>flag?47:53;\n",
        'src/worker.mjs':"import {parentPort} from 'node:worker_threads';import choose from './worker-choice.mjs';parentPort.postMessage(choose(false));\n",
        [DRIVER]:driver(`test('actual ESM worker graph',async()=>{
            const {pathToFileURL}=require('node:url');
            const choose=(await import(pathToFileURL(path.join(root,'src/worker-choice.mjs')).href)).default;
            assert.equal(choose(true),47);
            const {Worker}=await import('node:worker_threads');
            const worker=new Worker(pathToFileURL(path.join(root,'src/worker.mjs')));let value;
            worker.once('message',message=>value=message);
            await new Promise((resolve,reject)=>{worker.once('error',reject);worker.once('exit',code=>code?reject(Error('worker failed')):resolve())});
            assert.equal(value,53);
        });`)});
    const {result,exitCode}=await execute(f.root,{output:'reports/coverage/javascript-static/esm-worker.json',reportOnly:true});
    assert.equal(exitCode,0,result.error);assert.equal(result.merged.launched_workers,1);
    assert.deepEqual(Object.values(result.merged.coverage['src/worker-choice.mjs'].b)[0],[1,1]);
    assert.ok(result.merged.observed_sources.includes('src/worker.mjs'));
});
