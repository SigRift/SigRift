/* Generated from this authored source before launch; only built-ins load first. */
const fs = require('node:fs');
const path = require('node:path');
const { fileURLToPath } = require('node:url');
const { createHash } = require('node:crypto');
const { registerHooks } = require('node:module');
const KEY = Symbol.for('sigrift.node.ast.bootstrap.v2');
const SELF = 'tests/bridge/js/static_execution_bootstrap.cjs';
const GLOBAL = '__sigrift_static_coverage__';
const hash = value => createHash('sha256').update(value).digest('hex');
const canonical = value => JSON.stringify(value, (_key, item) => item && typeof item === 'object' && !Array.isArray(item)
    ? Object.fromEntries(Object.keys(item).sort().map(key => [key, item[key]])) : item);

if (globalThis[KEY]) throw new Error('Duplicate AST bootstrap');
if (!process.env.SIGRIFT_AST_PLAN || !process.env.SIGRIFT_AST_PARTS) throw new Error('Missing AST bootstrap configuration');
const planFile = path.resolve(process.env.SIGRIFT_AST_PLAN);
const plan = JSON.parse(fs.readFileSync(planFile));
const { checksum, ...payload } = plan;
if (hash(canonical(payload)) !== checksum || plan.schema !== 'sigrift-node-ast-plan-v2'
    || plan.producer.node !== process.version || typeof registerHooks !== 'function') throw new Error('AST bootstrap plan mismatch');
const programs = new Map(plan.programs.map(program => [program.id, program]));
const records = new Map(plan.baseline.entries.map(record => [record.id, record]));
const own = programs.get(SELF);
if (!own || path.resolve(__filename) !== path.join(path.dirname(planFile), 'bootstrap.cjs')
    || hash(fs.readFileSync(__filename)) !== records.get(SELF).generated_sha256
    || hash(fs.readFileSync(path.join(plan.root, SELF))) !== plan.producer.bootstrap_sha256
    || canonical(Object.keys(globalThis[GLOBAL] || {})) !== canonical([SELF])) throw new Error('Unbound AST bootstrap');
const pending = [SELF];
let observer = null;
const state = Object.freeze({
    filename: __filename,
    plan_sha256: checksum,
    subscribe(callback) {
        if (observer || typeof callback !== 'function') throw new Error('Invalid AST bootstrap subscription');
        observer = callback;
        for (const id of pending) observer(id);
        pending.length = 0;
    },
});
Object.defineProperty(globalThis, KEY, { value: state });
registerHooks({
    load(url, context, nextLoad) {
        const result = nextLoad(url, context);
        if (!url.startsWith('file:')) return result;
        const filename = fileURLToPath(url);
        const id = path.relative(plan.root, filename).split(path.sep).join('/');
        const program = programs.get(id);
        if (!program) return result;
        const record = records.get(id);
        if (!['commonjs', 'module'].includes(result.format) || result.source == null
            || hash(result.source) !== record.body_sha256 || hash(program.generated) !== record.generated_sha256) {
            throw new Error('Loaded module differs from source-bound plan');
        }
        let cursor = plan.root;
        for (const part of id.split('/')) {
            cursor = path.join(cursor, part);
            if (fs.lstatSync(cursor).isSymbolicLink()) throw new Error('Symlink module source');
        }
        if (hash(fs.readFileSync(filename)) !== record.body_sha256) throw new Error('Changed module source');
        if (observer) observer(id); else pending.push(id);
        return { ...result, source: program.generated };
    },
});
// A later loader could transform our generated return value after verification.
// This producer supports one source-bound loader chain, never that ambiguity.
const modules = require('node:module');
modules.registerHooks = modules.register = () => { throw new Error('Additional module loaders are not source-bound'); };
modules.syncBuiltinESMExports();
require(path.join(plan.root, 'tests/bridge/js/static_execution_preload.cjs'));
