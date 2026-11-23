/* Static Istanbul baseline only: no execution evidence or release pass. */
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { createHash } = require('node:crypto');
const { TextDecoder } = require('node:util');
const babel = require('@babel/parser');
const html = require('parse5');
const { createInstrumenter, readInitialCoverage } = require('istanbul-lib-instrument');
const { createCoverageMap } = require('istanbul-lib-coverage');

const ROOT = path.resolve(__dirname, '../../..');
const TOOL_DIRECTORY = 'tests/bridge/js';
const INPUTS = ['inventory.py', 'static_coverage.cjs', 'package.json', 'package-lock.json']
    .map(name => `${TOOL_DIRECTORY}/${name}`);
const DIRECT_TOOLS = ['@babel/parser', 'istanbul-lib-instrument', 'istanbul-lib-coverage', 'parse5'];
const COLLECTOR_SHA256 = hash(fs.readFileSync(__filename));
const OPTIONS = Object.freeze({
    coverageVariable: '__sigrift_static_coverage__',
    coverageGlobalScope: 'globalThis',
    coverageGlobalScopeFunc: false,
    reportLogic: false,
    ignoreClassMethods: [],
    parserPlugins: [],
    compact: false,
    preserveComments: false,
    produceSourceMap: false,
});
const INERT_TYPES = new Set(['application/json', 'application/ld+json', 'importmap', 'speculationrules']);
const CLASSIC_TYPES = new Set(['', 'text/javascript', 'application/javascript', 'text/ecmascript', 'application/ecmascript']);

function hash(value) { return createHash('sha256').update(value).digest('hex'); }
function canonical(value) {
    // Preserve JSON's omission/null rules for undefined optional Istanbul
    // locations, so a serialized artifact has the identical checksum.
    return JSON.stringify(value, (_key, item) => item && typeof item === 'object' && !Array.isArray(item)
        ? Object.fromEntries(Object.keys(item).sort().map(key => [key, item[key]])) : item);
}

function command(program, args, root) {
    const result = spawnSync(program, args, { cwd: root, encoding: 'utf8', timeout: 60000 });
    if (result.error) throw result.error;
    if (result.status !== 0) throw new Error(`${program} failed: ${result.stderr.trim()}`);
    return result.stdout;
}

function readSource(root, relative) {
    if (path.isAbsolute(relative) || relative.split('/').some(part => ['..', ''].includes(part))) {
        throw new Error(`Invalid source path: ${relative}`);
    }
    let current = root;
    for (const part of relative.split('/')) {
        current = path.join(current, part);
        if (fs.lstatSync(current).isSymbolicLink()) throw new Error(`Symlink source is unsupported: ${relative}`);
    }
    const bytes = fs.readFileSync(current);
    return { bytes, text: new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes) };
}

function inlineEntries(relative, source) {
    const entries = [];
    const document = html.parse(source, {
        sourceCodeLocationInfo: true,
        scriptingEnabled: true,
        onParseError(error) {
            // A DOM parser drops duplicate attributes; never drop authored code.
            if (error.code === 'duplicate-attribute') throw new Error(`Duplicate HTML attribute: ${relative}`);
        },
    });
    function add(kind, code, location, tagLocation, attribute = null, grammar = 'script') {
        if (!code.trim()) return;
        if (!location) throw new Error(`Missing inline source location: ${relative}`);
        const origin = {
            start: location.startOffset, end: location.endOffset,
            line: location.startLine, column: location.startCol,
            unit: 'UTF-16 code units; end exclusive', attribute,
        };
        entries.push({
            id: `${relative}#${kind}@${origin.start}:${origin.end}${attribute ? `:${attribute}` : ''}`,
            source_path: relative, kind, grammar, origin, code,
            raw_span_sha256: hash(source.slice(origin.start, origin.end)),
            // Match the existing conservative inventory independently of the
            // more precise body/attribute span used by this manifest.
            inventory_identity: {
                path: relative, kind, line: tagLocation.startLine,
                column: Array.from(source.slice(source.lastIndexOf('\n', tagLocation.startOffset - 1) + 1,
                    tagLocation.startOffset)).length + 1,
                sha256: hash(code),
            },
        });
    }
    function visit(node) {
        const location = node.sourceCodeLocation;
        const attributes = new Map((node.attrs || []).map(attr => [attr.name, attr.value]));
        for (const attr of node.attrs || []) {
            if (attr.value && attr.name.startsWith('on')) {
                add('event-handler', attr.value, location?.attrs?.[attr.name], location, attr.name, 'event-handler');
            }
            if (/^\s*javascript:/i.test(attr.value.replace(/[\t\n\r]/g, ''))) {
                // URL parsing/percent-decoding needs its own audited browser
                // adapter. Do not mislabel a string parse as URL execution.
                throw new Error(`JavaScript URL requires a source adapter: ${relative}`);
            }
        }
        if (node.tagName === 'script' && !attributes.get('src')) {
            const type = (attributes.get('type') || '').trim().toLowerCase();
            if (!INERT_TYPES.has(type)) {
                if (!CLASSIC_TYPES.has(type) && type !== 'module') {
                    throw new Error(`Unsupported inline script type: ${relative}`);
                }
                if (!location?.startTag || !location?.endTag) throw new Error(`Unclosed inline script: ${relative}`);
                const body = {
                    startOffset: location.startTag.endOffset, endOffset: location.endTag.startOffset,
                    startLine: location.startTag.endLine, startCol: location.startTag.endCol,
                };
                // Script text is raw text, unlike entity-decoded attributes.
                add('inline-script', source.slice(body.startOffset, body.endOffset), body, location,
                    null, type === 'module' ? 'module' : 'script');
            }
        }
        for (const child of node.childNodes || []) visit(child);
        if (node.content) visit(node.content); // Include dormant <template> code.
    }
    visit(document);
    return entries;
}

function instrument(entry) {
    const allowReturn = entry.grammar === 'event-handler' || entry.grammar === 'commonjs';
    const ast = babel.parse(entry.code, {
        sourceType: entry.grammar === 'module' ? 'module'
            : entry.grammar === 'unambiguous' ? 'unambiguous' : 'script',
        allowReturnOutsideFunction: allowReturn,
        plugins: OPTIONS.parserPlugins,
        errorRecovery: false,
    });
    for (const comment of ast.comments || []) {
        if (/\b(?:istanbul|c8|v8|node:coverage)\s+(?:ignore|disable)\b/i.test(comment.value)) {
            throw new Error(`Coverage suppression comment: ${entry.id}`);
        }
        if (/[@#]\s*sourceMappingURL\s*=/.test(comment.value)) {
            throw new Error(`Precompiled source map requires an explicit adapter: ${entry.id}`);
        }
    }
    if (readInitialCoverage(ast)) throw new Error(`Already instrumented source is not an authored baseline: ${entry.id}`);
    const grammar = entry.grammar === 'unambiguous' ? ast.program.sourceType : entry.grammar;
    const instrumenter = createInstrumenter({
        ...OPTIONS, esModules: grammar === 'module', autoWrap: allowReturn,
    });
    const generated = instrumenter.instrumentSync(entry.code, entry.id, false);
    const coverage = instrumenter.lastFileCoverage();
    if (!coverage || coverage.path !== entry.id) throw new Error(`No static map: ${entry.id}`);
    const maps = {
        statementMap: coverage.statementMap, fnMap: coverage.fnMap, branchMap: coverage.branchMap,
    };
    for (const [counter, map] of [['s', maps.statementMap], ['f', maps.fnMap], ['b', maps.branchMap]]) {
        if (canonical(Object.keys(coverage[counter])) !== canonical(Object.keys(map))) {
            throw new Error(`Incomplete static counters: ${entry.id}`);
        }
        for (const [key, value] of Object.entries(coverage[counter])) {
            const counts = counter === 'b' ? value : [value];
            if (!Array.isArray(counts) || counts.some(count => count !== 0)
                || (counter === 'b' && counts.length !== map[key].locations.length)) {
                throw new Error(`Baseline must contain every counter at zero: ${entry.id}`);
            }
        }
    }
    return {
        generated,
        record: {
            id: entry.id, source_path: entry.source_path, kind: entry.kind,
            grammar, origin: entry.origin || null,
            raw_span_sha256: entry.raw_span_sha256 || null,
            body_sha256: hash(entry.code), generated_sha256: hash(generated),
            map_sha256: hash(canonical(maps)), coverage,
        },
    };
}

function toolchain(root) {
    if (hash(readSource(root, `${TOOL_DIRECTORY}/static_coverage.cjs`).bytes) !== COLLECTOR_SHA256) {
        throw new Error('Running static collector differs from the source snapshot');
    }
    const packageInfo = JSON.parse(readSource(root, `${TOOL_DIRECTORY}/package.json`).text);
    const lock = JSON.parse(readSource(root, `${TOOL_DIRECTORY}/package-lock.json`).text);
    if (lock.lockfileVersion !== 3) throw new Error('Expected npm lockfile v3');
    const versions = {};
    for (const name of DIRECT_TOOLS) {
        const version = packageInfo.devDependencies[name];
        const locked = lock.packages[`node_modules/${name}`];
        const installed = JSON.parse(fs.readFileSync(path.join(__dirname, 'node_modules', name, 'package.json')));
        if (!/^\d+\.\d+\.\d+$/.test(version) || lock.packages[''].devDependencies[name] !== version
            || locked?.version !== version || installed.version !== version || !locked.integrity) {
            throw new Error(`Pinned measurement dependency mismatch: ${name}`);
        }
        versions[name] = version;
    }
    // Bind every installed transitive version to the same integrity-bearing
    // lock, not just the public instrumenter version. npm ci verifies tarballs.
    for (const [name, locked] of Object.entries(lock.packages)) {
        if (!name) continue;
        if (!name.startsWith('node_modules/') || name.split('/').includes('..') || !locked.integrity) {
            throw new Error('Unsupported measurement lock entry');
        }
        const installed = JSON.parse(fs.readFileSync(path.join(__dirname, name, 'package.json')));
        if (installed.version !== locked.version) throw new Error(`Installed lock mismatch: ${name}`);
    }
    return { node: process.version, direct_dependencies: versions,
        instrumenter_options: JSON.parse(canonical(OPTIONS)) };
}

function buildBaseline(root = ROOT, { allowDirty = false } = {}) {
    root = path.resolve(root);
    const inventory = JSON.parse(command('python3', [path.join(root, TOOL_DIRECTORY, 'inventory.py')], root));
    const tracked = command('git', ['ls-files', '--cached', '--others', '--exclude-standard', '-z'], root)
        .split('\0').filter(Boolean);
    const htmlFiles = [...new Set(tracked.filter(name => /\.html?$/i.test(name)))].sort();
    if (inventory.test_exclusions.length) throw new Error("Authored test exclusions are forbidden");
    const files = [...inventory.files].sort();
    if (!files.length || new Set(files).size !== files.length) throw new Error('Empty or duplicate JavaScript inventory');
    // A tracked deletion must not disappear through the older inventory's
    // is_file() check. Resolve every non-excluded authored source explicitly.
    const expected = [...new Set(tracked.filter(name => /\.(js|mjs|cjs)$/.test(name)
        && !inventory.exclusions.includes(name)))].sort();
    if (canonical(files) !== canonical(expected)) throw new Error('JavaScript source inventory mismatch');
    const inputs = [...new Set([...files, ...htmlFiles, ...INPUTS])].sort();
    const sources = new Map(inputs.map(name => [name, readSource(root, name)]));
    const commit = command('git', ['rev-parse', 'HEAD'], root).trim();
    const committed = new Set(command('git', ['ls-tree', '-r', '--name-only', '-z', commit], root).split('\0'));
    // A staged deletion no longer appears in ls-files or the current inputs.
    const removedInputs = [...committed].some(name => !inputs.includes(name)
        && (INPUTS.includes(name) || /\.html?$/i.test(name)
            || (/\.(js|mjs|cjs)$/.test(name) && !inventory.exclusions.includes(name))));
    // Git's clean status can hide checkout filters / assume-unchanged files.
    // Clean provenance additionally means the exact bytes at the commit.
    const byteChanges = inputs.some(name => !committed.has(name)
        || hash(command('git', ['show', `${commit}:${name}`], root)) !== hash(sources.get(name).bytes));
    const dirty = removedInputs || byteChanges
        || Boolean(command('git', ['status', '--porcelain', '--untracked-files=all', '--', ...inputs], root));
    if (dirty && !allowDirty) throw new Error('Dirty JavaScript measurement inputs; commit or explicitly mark a development baseline');
    const inline = htmlFiles.flatMap(name => inlineEntries(name, sources.get(name).text));
    const oldIdentities = inventory.unmeasured_inline.map(canonical).sort();
    const identities = inline.map(entry => canonical(entry.inventory_identity)).sort();
    if (canonical(oldIdentities) !== canonical(identities)) throw new Error('Inline inventory disagreement; inspect source adapters');
    const entries = files.map(name => ({
        id: name, source_path: name, kind: 'file', code: sources.get(name).text,
        grammar: name.endsWith('.mjs') ? 'module' : name.endsWith('.cjs') ? 'commonjs' : 'unambiguous',
    })).concat(inline).sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
    if (new Set(entries.map(entry => entry.id)).size !== entries.length) throw new Error('Duplicate coverage origin');
    const records = entries.map(entry => instrument(entry).record);
    const coverageMap = createCoverageMap({});
    for (const record of records) coverageMap.addFileCoverage(record.coverage);
    const result = {
        schema: 'sigrift-javascript-static-v1',
        status: 'baseline-only-no-execution',
        source: {
            commit, dirty,
            inputs: inputs.map(name => ({ path: name, sha256: hash(sources.get(name).bytes) })),
        },
        measurement: toolchain(root),
        inventory: { files, html_files: htmlFiles, inline_behaviors: inline.length,
            vendor_exclusions: inventory.exclusions, collected_test_exclusions: inventory.test_exclusions },
        limitations: [
            'No execution results: all static counters are zero; this artifact cannot satisfy a release coverage gate.',
            'Tool provenance relies on trusted npm ci with the locked integrity checks; installed package versions are checked, not installed module bytes attested.',
            'Istanbul branch locations cover its AST model, not every control-flow edge (for example loop exits or optional chaining).',
            'Inline counters use decoded body coordinates; original HTML spans are UTF-16 and source/hash bound.',
            'JavaScript URLs, unknown script types and precompiled source maps fail closed pending explicit adapters.',
            'Browser/Node execution, instrumented response identity, counter import and failure-safe collection are not integrated.',
        ],
        entries: records,
        totals: coverageMap.getCoverageSummary().toJSON(),
    };
    if (command('git', ['rev-parse', 'HEAD'], root).trim() !== commit
        || inputs.some(name => hash(readSource(root, name).bytes) !== hash(sources.get(name).bytes))
        || canonical(command('git', ['ls-files', '--cached', '--others', '--exclude-standard', '-z'], root)
            .split('\0').filter(Boolean)) !== canonical(tracked)) {
        throw new Error('Source changed during static baseline generation');
    }
    return { ...result, manifest_sha256: hash(canonical(result)) };
}

function verifyBaseline(baseline, root = ROOT, options = {}) {
    const { manifest_sha256: checksum, ...payload } = baseline;
    if (checksum !== hash(canonical(payload))) throw new Error('Static manifest checksum mismatch');
    const current = buildBaseline(root, options);
    if (canonical(current) !== canonical(baseline)) {
        throw new Error('Static baseline differs from current source, inventory, maps or measurement configuration');
    }
    return current;
}

function outputDestination(value, root = ROOT) {
    const base = path.join(root, 'reports/coverage/javascript-static');
    const target = path.resolve(root, value);
    if (!target.startsWith(base + path.sep) || path.extname(target) !== '.json') {
        throw new Error('Write a new JSON report beneath reports/coverage/javascript-static');
    }
    const relative = path.relative(root, target);
    if (command('git', ['ls-files', '--cached', '-z', '--', relative], root)) {
        throw new Error('Refusing to overwrite a tracked measurement/source file');
    }
    let current = root;
    for (const component of relative.split(path.sep)) {
        current = path.join(current, component);
        let info;
        try { info = fs.lstatSync(current); } catch (error) {
            if (error.code !== 'ENOENT') throw error;
            continue;
        }
        if (info.isSymbolicLink()) throw new Error('Refusing a symlink output or parent');
        if (current === target) throw new Error('Refusing to overwrite an existing output (including hard links)');
        if (!info.isDirectory()) throw new Error('Output parent must be a directory');
    }
    return target;
}

function main(args = process.argv.slice(2)) {
    const allowed = args.every(arg => arg === '--allow-dirty' || arg.startsWith('--output=') || arg.startsWith('--verify-baseline='));
    const output = args.filter(arg => arg.startsWith('--output='));
    const verify = args.filter(arg => arg.startsWith('--verify-baseline='));
    if (!allowed || output.length + verify.length !== 1) {
        throw new Error('Usage: node tests/bridge/js/static_coverage.cjs (--output=reports/coverage/javascript-static/NEW.json | --verify-baseline=FILE) [--allow-dirty]');
    }
    const target = output.length ? outputDestination(output[0].slice('--output='.length)) : null;
    const options = { allowDirty: args.includes('--allow-dirty') };
    const result = verify.length
        ? verifyBaseline(JSON.parse(fs.readFileSync(verify[0].slice('--verify-baseline='.length))), ROOT, options)
        : buildBaseline(ROOT, options);
    if (output.length) {
        outputDestination(target); // Check again immediately before writing.
        fs.mkdirSync(path.dirname(target), { recursive: true });
        fs.writeFileSync(target, JSON.stringify(result, null, 2) + '\n', { flag: 'wx' });
    }
    console.log(JSON.stringify({ status: result.status, source: result.source.commit, dirty: result.source.dirty,
        files: result.inventory.files.length, inline_behaviors: result.inventory.inline_behaviors,
        totals: result.totals, manifest_sha256: result.manifest_sha256 }, null, 2));
}

module.exports = { buildBaseline, verifyBaseline, inlineEntries, instrument, canonical, hash, main };
if (require.main === module) {
    try { main(); } catch (error) { console.error(error.message); process.exitCode = 1; }
}
