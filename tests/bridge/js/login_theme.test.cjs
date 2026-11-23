const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const sourcePath = path.join(__dirname, '../../../src/sigrift/bridge/static/login_theme.js');
const source = fs.readFileSync(sourcePath, 'utf8');

for (const [search, expected] of [
    ['', 'dark'], ['?theme=dark', 'dark'], ['?theme=light', 'light'],
    ['?theme=matrix', 'dark'], ['?theme=LIGHT', 'dark'],
    ['?theme=%3Cscript%3E', 'dark'],
]) {
    test(`unauthenticated theme ${search || '(default)'} resolves to ${expected}`, () => {
        const attributes = new Map();
        vm.runInNewContext(source, {
            window: { location: { search } }, URLSearchParams,
            document: { documentElement: { setAttribute: (key, value) => attributes.set(key, value) } },
        }, { filename: sourcePath });
        assert.deepEqual([...attributes], [['data-theme', expected]]);
    });
}

test('unavailable URL parsing preserves the neutral default theme', () => {
    const attributes = new Map();
    vm.runInNewContext(source, {
        window: { location: { search: '?theme=light' } },
        document: { documentElement: { setAttribute: (key, value) => attributes.set(key, value) } },
        // Older/restricted environments may not expose URLSearchParams.
    }, { filename: sourcePath });
    assert.equal(attributes.get('data-theme'), 'dark');
});
