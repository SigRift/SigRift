/* Shipped admin key list: the Expires cell and EXPIRED are the server's reading of the stored expiry, not the browser's. */
// Local time 7 hours west of UTC (before any Date is made), so a naive stored
// date read as local time shows a different instant here, also on a UTC host.
process.env.TZ = 'Etc/GMT+7';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const filename = path.resolve(__dirname, '../../../src/sigrift/bridge/static/admin.js');

/* A <div> holding one text node, serialised like the DOM does (esc() itself
 * escapes & < > " ' as text, so quotes show as &quot; in the markup). */
class TextHolder {
    constructor() { this.text = ''; }
    appendChild(node) { this.text += node.textContent; return node; }
    get innerHTML() { return this.text.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;'); }
}

function render(rows) {
    const tbody = { innerHTML: '', querySelectorAll: () => [] };
    const elements = { 'keys-tbody': tbody, 'keys-empty': { style: {} } };
    const context = {
        console,
        document: {
            addEventListener() {}, createElement: () => new TextHolder(), createTextNode: textContent => ({ textContent }),
            getElementById: id => elements[id] || null,
        },
        window: {}, setTimeout() {},
    };
    vm.runInNewContext(fs.readFileSync(filename, 'utf8'), context, { filename });
    const panel = Object.create(context.AdminPanel.prototype);
    panel._renderKeys(rows);
    return [...tbody.innerHTML.matchAll(/data-label="Expires">(.*?)<\/td>/g)].map(m => m[1]);
}

/* One /api/admin/keys row, as the bridge lists it: the stored value, the
   instant bridge auth applies (null: none, or unparseable) and its verdict. */
function row(expires_at, expired, effective_expires_at = null) {
    return {
        key_id: 'k', is_master: false, role: 'viewer', stored_role: 'viewer', description: '', created_at: '',
        expires_at, effective_expires_at, expired, node_id: null,
    };
}

const badge = '<span class="admin-badge expired">EXPIRED</span>';

/* An instant as the cell shows it: this browser's local time, with the year. */
function shown(iso) {
    return new Date(iso).toLocaleString(undefined, {
        hour12: false, year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit',
    });
}

test('the test runs 7 hours west of UTC', () => {
    assert.equal(new Date(2026, 10, 10).getTimezoneOffset(), 420);
});

for (const [name, stored, shownAs] of [
    ['an unparseable value', 'soon', '<code>soon</code>'],
    ['a date only the browser can read', 'Jan 1 2999', '<code>Jan 1 2999</code>'],
    ['a slash date only the browser can read', '2999/01/01', '<code>2999/01/01</code>'],
    ['a bare number string', '1', '<code>1</code>'],
    ['a number', 12345, '<code>12345</code>'],
    ['a list', ['2999-01-01'], '<code>[&quot;2999-01-01&quot;]</code>'],
    ['string markup', '<img src=x onerror=alert(1)>', '<code>&lt;img src=x onerror=alert(1)&gt;</code>'],
    ['markup in a list', ['<img src=x onerror=alert(1)>'], '<code>[&quot;&lt;img src=x onerror=alert(1)&gt;&quot;]</code>'],
    ['markup in an object', { '<b>': '</td><script>' }, '<code>{&quot;&lt;b&gt;&quot;:&quot;&lt;/td&gt;&lt;script&gt;&quot;}</code>'],
]) {
    test('a stored expiry bridge auth cannot parse (' + name + ') shows as stored, escaped, and EXPIRED', () => {
        const [cell] = render([row(stored, true, null)]);
        assert.equal(cell, shownAs + ' ' + badge);
        assert.doesNotMatch(cell, /Invalid Date|<img|<b>|<script>/);
    });
}

test('a naive stored date shows the UTC instant auth applies, not the browser reading it as local time', () => {
    const [cell] = render([row('2026-11-10T00:00:00', true, '2026-11-10T00:00:00+00:00')]);
    assert.equal(cell, shown('2026-11-10T00:00:00Z') + ' ' + badge);
    // Read as local time here it would be 7 hours later: a date not yet reached.
    assert.notEqual(shown('2026-11-10T00:00:00Z'), shown('2026-11-10T00:00:00'));
});

test('a padded or offset stored date shows the instant auth applies', () => {
    assert.deepEqual(
        render([
            row(' 2020-01-01T00:00:00+00:00 ', true, '2020-01-01T00:00:00+00:00'),
            row('2999-01-01T02:00:00+02:00', false, '2999-01-01T02:00:00+02:00'),
        ]),
        [shown('2020-01-01T00:00:00Z') + ' ' + badge, shown('2999-01-01T00:00:00Z')],
    );
});

test('the year is shown: 2020 and 2999 on the same day and time do not read alike', () => {
    const [past, future] = render([
        row('2020-06-01T12:00:00+00:00', true, '2020-06-01T12:00:00+00:00'),
        row('2999-06-01T12:00:00+00:00', false, '2999-06-01T12:00:00+00:00'),
    ]);
    assert.equal(past, shown('2020-06-01T12:00:00Z') + ' ' + badge);
    assert.equal(future, shown('2999-06-01T12:00:00Z'));
    assert.notEqual(past.replace(' ' + badge, ''), future);
});

test('an instant this browser cannot read shows the stored value, never "Invalid Date"', () => {
    const [cell] = render([row('2999-01-01T00:00:00+05:30:15', false, '2999-01-01T00:00:00+05:30:15')]);
    assert.equal(cell, '<code>2999-01-01T00:00:00+05:30:15</code>');
});

test('the server decides, not the browser clock: a past date the server rejects is EXPIRED', () => {
    const [cell] = render([row('2020-01-01T00:00:00+00:00', true, '2020-01-01T00:00:00+00:00')]);
    assert.equal(cell, shown('2020-01-01T00:00:00Z') + ' ' + badge);
});

test('the server decides, not the browser clock: a future date the server rejects is EXPIRED', () => {
    const [cell] = render([row('2999-01-01T00:00:00+00:00', true, '2999-01-01T00:00:00+00:00')]);
    assert.equal(cell, shown('2999-01-01T00:00:00Z') + ' ' + badge);
});

test('the server decides, not the browser clock: a past date the server still accepts has no badge', () => {
    const [cell] = render([row('2020-01-01T00:00:00+00:00', false, '2020-01-01T00:00:00+00:00')]);
    assert.equal(cell, shown('2020-01-01T00:00:00Z'));
});

/* "\x1c" is blank to bridge auth (Python str.strip), not to String.prototype.trim. */
for (const [name, stored] of [['null', null], ['empty', ''], ['blank', '   '], ['blank to the server only', '\x1c']]) {
    test('no expiry (' + name + ') shows -- without a badge', () => {
        assert.deepEqual(render([row(stored, false, null)]), ['--']);
    });
}

test('a key accepted until a future date shows the date without a badge', () => {
    const [cell] = render([row('2999-01-01T00:00:00+00:00', false, '2999-01-01T00:00:00+00:00')]);
    assert.equal(cell, shown('2999-01-01T00:00:00Z'));
});

test('only the server\'s explicit verdict badges a key: a row without `expired` has no badge', () => {
    const { expired, ...unjudged } = row('2999-01-01T00:00:00+00:00', true, '2999-01-01T00:00:00+00:00');
    assert.equal(expired, true);
    assert.deepEqual(render([unjudged]), [shown('2999-01-01T00:00:00Z')]);
});

test('each row gets its own verdict', () => {
    assert.deepEqual(
        render([row('soon', true), row(null, false), row('2999-01-01T00:00:00Z', false, '2999-01-01T00:00:00+00:00'), row('also bad', true)]),
        ['<code>soon</code> ' + badge, '--', shown('2999-01-01T00:00:00Z'), '<code>also bad</code> ' + badge],
    );
});
