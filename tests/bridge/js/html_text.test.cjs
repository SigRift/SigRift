const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const filename = path.resolve(__dirname, '../../../src/sigrift/bridge/static/html_text.js');
const context = vm.createContext({ window: {} });
vm.runInContext(fs.readFileSync(filename, 'utf8'), context, { filename });
const decode = context.window.decodeHtmlEscapedText;

test('Python escaped punctuation becomes plain text without parsing markup', () => {
    assert.equal(decode('Operator&#x27;s &quot;RF&quot; &amp; &lt;img src=x onerror=alert(1)&gt;'),
        'Operator\'s "RF" & <img src=x onerror=alert(1)>');
});

test('a single pass preserves intentional entities and ambiguous legacy layers', () => {
    assert.equal(decode('&amp;amp; &amp;lt; &amp;#x27;'), '&amp; &lt; &#x27;');
    assert.equal(decode('&amp;amp;amp;'), '&amp;amp;');
    assert.equal(decode('&#39; &#X27; &copy; &unknown; &amp'), '&#39; &#X27; &copy; &unknown; &amp');
});

test('plain and missing display values stay plain text', () => {
    assert.equal(decode('RF Ω <b>literal</b>'), 'RF Ω <b>literal</b>');
    assert.equal(decode(null), '');
    assert.equal(decode(undefined), '');
    assert.equal(decode(0), '0');
});
