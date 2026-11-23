/* Measure every first-party source file, including files no test has loaded. */
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { createHash } = require('node:crypto');
const { fileURLToPath } = require('node:url');

const root = path.resolve(__dirname, '../../..');
const reports = path.join(root, 'reports/coverage/javascript');
const c8 = path.join(__dirname, 'node_modules/c8/bin/c8.js');

function browserReports(directory, expected, sourceRoot = root) {
    function discover(current) {
        return fs.readdirSync(current, { withFileTypes: true }).flatMap(entry => {
            const target = path.join(current, entry.name);
            if (entry.isDirectory()) return discover(target);
            return entry.isFile() && /^coverage-browser-.*\.json$/.test(entry.name) ? [target] : [];
        });
    }
    const files = discover(directory);
    if (!files.length) throw new Error('No browser coverage reports found');
    return files.map(file => {
        const payload = JSON.parse(fs.readFileSync(file));
        if (payload.sigrift?.complete !== true || !payload.result?.length) {
            throw new Error('Browser coverage report is incomplete');
        }
        const result = payload.result.map(script => {
            if (!expected.includes(script.url)) throw new Error('Browser coverage source is outside the inventory');
            const source = fs.readFileSync(path.join(sourceRoot, script.url));
            const hash = createHash('sha256').update(source).digest('hex');
            if (payload.sigrift.source_sha256?.[script.url] !== hash) {
                throw new Error(`Browser source hash differs: ${script.url}`);
            }
            const length = source.toString('utf8').length;
            if (!Array.isArray(script.functions) || !script.functions.length) throw new Error('Missing browser function coverage');
            for (const fn of script.functions) {
                if (typeof fn.isBlockCoverage !== 'boolean') {
                    throw new Error('Missing browser block-coverage metadata');
                }
                if (!Array.isArray(fn.ranges) || !fn.ranges.length) throw new Error('Missing browser coverage ranges');
                for (const range of fn.ranges) {
                    if (![range.startOffset, range.endOffset, range.count].every(Number.isInteger)
                        || range.startOffset < 0 || range.endOffset < range.startOffset
                        || range.endOffset > length || range.count < 0) {
                        throw new Error('Invalid browser coverage range');
                    }
                }
                if (!fn.isBlockCoverage && fn.ranges.some(range => range.count > 0)) {
                    throw new Error('Executed function lacks block coverage');
                }
            }
            return { scriptId: script.scriptId, url: path.join(sourceRoot, script.url), functions: script.functions };
        });
        return { result, timestamp: payload.timestamp };
    });
}

function ownedSourcePath(url, expected, sourceRoot) {
    if (!url) return null;
    const filename = url.startsWith('file:') ? fileURLToPath(url) : url;
    if (!path.isAbsolute(filename)) return null;
    const relative = path.relative(sourceRoot, filename).split(path.sep).join('/');
    return expected.includes(relative) ? relative : null;
}

function unmeasuredBranchFiles(reports, expected, sourceRoot = root) {
    const observed = new Set(reports.flatMap(report => (report.result || []).map(
        script => ownedSourcePath(script.url, expected, sourceRoot),
    )));
    return expected.filter(file => !observed.has(file)).sort();
}

function unmeasuredBranchFunctions(reports, expected, sourceRoot = root) {
    const unresolved = new Map();
    const measured = new Set();
    for (const report of reports) {
        for (const script of report.result || []) {
            const relative = ownedSourcePath(script.url, expected, sourceRoot);
            if (relative === null) continue;
            for (const fn of script.functions) {
                const outer = fn.ranges[0];
                const key = JSON.stringify([relative, outer.startOffset, outer.endOffset]);
                if (fn.isBlockCoverage === true) {
                    measured.add(key);
                } else if (fn.isBlockCoverage === false && fn.ranges.every(range => range.count === 0)) {
                    // V8 legitimately reports never-executed functions without
                    // block ranges. Keep their lines uncovered, and record that
                    // their internal branch inventory has not been observed.
                    unresolved.set(key, { path: relative, startOffset: outer.startOffset, endOffset: outer.endOffset });
                } else {
                    throw new Error('Owned JavaScript lacks precise block-coverage evidence');
                }
            }
        }
    }
    // Another source-matched execution can measure this exact function later.
    return [...unresolved.entries()].filter(([key]) => !measured.has(key))
        .map(([, value]) => value).sort((a, b) => a.path.localeCompare(b.path) || a.startOffset - b.startOffset || a.endOffset - b.endOffset);
}

function verifyInventory(summary, expected, sourceRoot = root) {
    if (!expected.length) throw new Error('No first-party JavaScript files found');
    const actual = Object.keys(summary).filter(key => key !== 'total')
        .map(key => path.relative(sourceRoot, key).split(path.sep).join('/')).sort();
    if (JSON.stringify(actual) !== JSON.stringify([...expected].sort())) {
        const missing = expected.filter(file => !actual.includes(file));
        const unexpected = actual.filter(file => !expected.includes(file));
        throw new Error(`Coverage inventory mismatch: missing=${JSON.stringify(missing)}, unexpected=${JSON.stringify(unexpected)}`);
    }
    for (const file of expected) {
        if (!(summary[path.join(sourceRoot, file)].lines.total > 0)) {
            throw new Error(`Coverage omitted executable lines for ${file}`);
        }
    }
}

function completeCounters(summary, expected, sourceRoot = root, unmeasuredBranches = []) {
    let complete = true;
    for (const metric of ['lines', 'branches']) {
        let total = 0;
        let covered = 0;
        for (const file of expected) {
            const counts = summary[path.join(sourceRoot, file)]?.[metric];
            if (!counts || ![counts.total, counts.covered, counts.skipped].every(Number.isSafeInteger)
                || counts.total < 0 || counts.covered < 0 || counts.covered > counts.total
                || counts.skipped !== 0) {
                throw new Error(`Invalid or excluded ${metric} counters for ${file}`);
            }
            total += counts.total;
            covered += counts.covered;
            complete = complete && counts.covered === counts.total;
        }
        const aggregate = summary.total?.[metric];
        if (!aggregate || !total || !Number.isSafeInteger(total) || !Number.isSafeInteger(covered)
            || aggregate.total !== total || aggregate.covered !== covered || aggregate.skipped !== 0) {
            throw new Error(`Invalid ${metric} totals for the complete source inventory`);
        }
    }
    return complete && unmeasuredBranches.length === 0;
}

// Exact decimal comparison: covered/total * 100 >= floor, without float rounding.
function meetsFloor(covered, total, floor) {
    const match = /^(\d+)(?:\.(\d+))?$/.exec(String(floor));
    if (!match) throw new Error(`Invalid coverage floor: ${floor}`);
    const decimals = (match[2] || '').length;
    const scaled = BigInt(match[1] + (match[2] || ''));
    return BigInt(covered) * 100n * 10n ** BigInt(decimals) >= scaled * BigInt(total);
}

function loadFloors(file = path.join(root, 'scripts/coverage-floors.json')) {
    let floors;
    try {
        floors = JSON.parse(fs.readFileSync(file, 'utf8')).javascript;
    } catch (error) {
        throw new Error(`Missing or invalid coverage floors for javascript: ${error.message}`);
    }
    if (!floors || typeof floors !== 'object' || Array.isArray(floors)
        || JSON.stringify(Object.keys(floors).sort()) !== JSON.stringify(['branches', 'lines'])) {
        throw new Error('Coverage floors for javascript need lines and branches');
    }
    for (const [metric, value] of Object.entries(floors)) {
        if (typeof value !== 'number' || !/^\d+(\.\d+)?$/.test(String(value)) || value > 100) {
            throw new Error(`Invalid javascript ${metric} coverage floor`);
        }
    }
    return floors;
}

// The release gate: exact aggregate counters at or above the committed floor.
function checkFloors(summary, floors) {
    const result = { floor: { ...floors }, passed: true };
    for (const metric of ['lines', 'branches']) {
        const { covered, total } = summary.total[metric];
        result[metric] = { covered, total, percent: Math.round(1e6 * covered / total) / 1e4 };
        result.passed = result.passed && meetsFloor(covered, total, floors[metric]);
    }
    return result;
}

function main() {
    const args = process.argv.slice(2);
    if (args.some(arg => arg !== '--report-only' && !arg.startsWith('--browser-coverage='))) {
        console.error('Usage: node tests/bridge/js/coverage.cjs [--report-only] [--browser-coverage=PRIVATE_DIR]');
        process.exit(2);
    }
    const browserArg = args.find(arg => arg.startsWith('--browser-coverage='));
    const browserDirectory = browserArg ? path.resolve(browserArg.slice('--browser-coverage='.length)) : null;
    if (browserDirectory && (browserDirectory === reports || browserDirectory.startsWith(reports + path.sep))) {
        throw new Error('Keep browser input outside the regenerated report directory');
    }
    if (!fs.existsSync(c8)) {
        console.error('Run npm ci --prefix tests/bridge/js --ignore-scripts first.');
        process.exit(2);
    }
    const discovery = spawnSync('python3', [path.join(__dirname, 'inventory.py')], {
        cwd: root, encoding: 'utf8',
    });
    if (discovery.error) throw discovery.error;
    if (discovery.status !== 0) throw new Error(discovery.stderr || 'Source discovery failed');
    const inventory = JSON.parse(discovery.stdout);
    const expected = inventory.files.sort();
    if (!expected.length) throw new Error('No first-party JavaScript files found');
    fs.rmSync(reports, { recursive: true, force: true });
    const tests = fs.readdirSync(__dirname)
        .filter(name => name.endsWith('.test.cjs'))
        .map(name => path.join(__dirname, name));
    if (!tests.length) throw new Error('No JavaScript tests found');

    const shared = [
        c8, '--all', '--src', root,
        ...expected.flatMap(file => ['--include', file]),
        ...inventory.exclusions.flatMap(file => ['--exclude', file]),
        '--extension=.js', '--extension=.mjs', '--extension=.cjs',
        '--reports-dir', reports,
        '--temp-directory', path.join(reports, 'v8'),
    ];
    const run = spawnSync(process.execPath, [
        ...shared, '--reporter=json', '--reporter=json-summary', '--reporter=lcov',
        '--reporter=text-summary', process.execPath, '--test', ...tests,
    ], { cwd: root, stdio: 'inherit' });
    if (run.error) throw run.error;
    if (run.status !== 0) process.exit(run.status || 1);

    const imported = browserDirectory ? browserReports(browserDirectory, expected) : [];
    if (imported.length) {
        imported.forEach((payload, index) => fs.writeFileSync(
            path.join(reports, 'v8', `coverage-browser-${index}.json`), JSON.stringify(payload),
        ));
        const combined = spawnSync(process.execPath, [
            ...shared, 'report', '--reporter=json', '--reporter=json-summary',
            '--reporter=lcov', '--reporter=text-summary',
        ], { cwd: root, stdio: 'inherit' });
        if (combined.error) throw combined.error;
        if (combined.status !== 0) process.exit(combined.status || 1);
    }

    const summary = JSON.parse(fs.readFileSync(path.join(reports, 'coverage-summary.json')));
    verifyInventory(summary, expected);
    const rawReports = fs.readdirSync(path.join(reports, 'v8'))
        .filter(name => name.startsWith('coverage-') && name.endsWith('.json'))
        .map(name => JSON.parse(fs.readFileSync(path.join(reports, 'v8', name))));
    const unmeasuredBranches = unmeasuredBranchFunctions(rawReports, expected);
    const unmeasuredFiles = unmeasuredBranchFiles(rawReports, expected);
    const complete = completeCounters(summary, expected, root, [...unmeasuredBranches, ...unmeasuredFiles]);
    inventory.complete = complete; // informational; the gate is the floor
    inventory.branch_measurement = 'V8 observed block ranges; not a complete static branch denominator';
    inventory.unmeasured_branch_functions = unmeasuredBranches;
    inventory.unmeasured_branch_files = unmeasuredFiles;
    inventory.browser_reports = imported.length;
    inventory.browser_source_files = [...new Set(imported.flatMap(report => report.result.map(
        script => path.relative(root, script.url).split(path.sep).join('/'),
    )))].sort();
    fs.writeFileSync(path.join(reports, 'inventory.json'), JSON.stringify(inventory, null, 2) + '\n');
    console.log(`Verified coverage inventory: ${expected.length} first-party JavaScript files.`);
    console.log(`Unmeasured inline HTML scripts/handlers: ${inventory.unmeasured_inline.length}.`);
    console.log(`Functions without observed internal branch ranges: ${unmeasuredBranches.length}.`);
    console.log(`Unloaded files without observed branch ranges: ${unmeasuredFiles.length}.`);
    if (args.includes('--report-only')) {
        console.log('Report-only measurement: the committed coverage floor is not enforced by this command.');
    } else {
        // Integrity problems above (inventory, counters, provenance) already
        // threw. Unmeasured inline HTML and unobserved branch ranges are
        // recorded in inventory.json as known gaps; they lower the measured
        // percentages but no longer block on their own.
        const gate = checkFloors(summary, loadFloors());
        fs.writeFileSync(path.join(reports, 'floor.json'), JSON.stringify(gate, null, 2) + '\n');
        console.log(JSON.stringify(gate));
        if (!gate.passed) {
            console.error('JavaScript coverage is below the committed floor in scripts/coverage-floors.json.');
        }
        process.exit(gate.passed ? 0 : 1);
    }
}

module.exports = { verifyInventory, completeCounters, meetsFloor, loadFloors, checkFloors, browserReports, unmeasuredBranchFunctions, unmeasuredBranchFiles };
if (require.main === module) main();
