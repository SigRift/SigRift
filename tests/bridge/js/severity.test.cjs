const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const filename = path.resolve(__dirname, '../../../src/sigrift/bridge/static/severity.js');
const context = vm.createContext({ window: {} });
vm.runInContext(fs.readFileSync(filename, 'utf8'), context, { filename });
const severityIcon = context.window.severityIcon;

test('each supported severity has a distinct non-color cue without duplicate screen-reader text', () => {
    const icons = ['critical', 'high', 'warning', 'info'].map(severityIcon);
    assert.equal(new Set(icons).size, 4);
    for (const icon of icons) {
        assert.match(icon, /^<span class="severity-icon" aria-hidden="true">[^<]+<\/span>$/u);
    }
});

test('case differences in severity labels preserve the same visual cue', () => {
    for (const severity of ['critical', 'high', 'warning', 'info']) {
        assert.equal(severityIcon(severity.toUpperCase()), severityIcon(severity));
    }
});

test('missing, unknown, and HTML-shaped values produce no decorative markup', () => {
    for (const severity of [undefined, null, '', 'unknown', '<img src=x onerror=alert(1)>']) {
        assert.equal(severityIcon(severity), '');
    }
});
