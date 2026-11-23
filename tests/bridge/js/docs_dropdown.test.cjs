const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const root = path.resolve(__dirname, '../../..');
const filename = path.join(root, 'src/sigrift/bridge/static/docs_dropdown.js');

class Element {
    constructor(className = '') {
        this.classes = new Set(className.split(' ').filter(Boolean));
        this.children = []; this.parentElement = null; this.handlers = {};
        const classes = this.classes;
        this.classList = {
            contains: name => classes.has(name),
            remove: name => classes.delete(name),
            toggle: name => (classes.has(name) ? (classes.delete(name), false) : (classes.add(name), true)),
        };
    }
    get nextElementSibling() {
        const siblings = this.parentElement ? this.parentElement.children : [];
        return siblings[siblings.indexOf(this) + 1] || null;
    }
    appendChild(child) { this.children.push(child); child.parentElement = this; return child; }
    contains(target) { return target === this || this.children.some(child => child.contains(target)); }
    addEventListener(type, handler) { (this.handlers[type] ||= []).push(handler); }
    matches(selector) { return selector.split(' ').pop().split('.').filter(Boolean).every(name => this.classes.has(name)); }
    descendants() { return this.children.flatMap(child => [child, ...child.descendants()]); }
    click() {
        const event = {target: this, type: 'click'};
        for (let node = this; node; node = node.parentElement) {
            for (const handler of node.handlers.click || []) handler.call(node, event);
        }
    }
}

function header() {
    const dropdown = new Element('docs-dropdown');
    const button = dropdown.appendChild(new Element('help-icon'));
    const menu = dropdown.appendChild(new Element('docs-dropdown-menu'));
    const link = menu.appendChild(new Element());
    return {dropdown, button, menu, link};
}

/* The dashboard and admin pages: one header dropdown each, plus page content. */
function page(readyState, count = 1) {
    const document = new Element('document');
    document.readyState = readyState;
    const body = document.appendChild(new Element('body'));
    const headers = Array.from({length: count}, () => header());
    for (const h of headers) body.appendChild(h.dropdown);
    const outside = body.appendChild(new Element('card'));
    document.querySelectorAll = selector => {
        // ".docs-dropdown .help-icon": a .help-icon inside a .docs-dropdown.
        const [ancestor, own] = selector.includes(' ') ? selector.split(' ') : [null, selector];
        return document.descendants().filter(el => el.matches(own)
            && (!ancestor || (el.parentElement && el.parentElement.matches(ancestor))));
    };
    vm.runInNewContext(fs.readFileSync(filename, 'utf8'), {document}, {filename});
    const ready = () => (document.handlers.DOMContentLoaded || []).forEach(handler => handler({}));
    return {document, headers, outside, ready};
}

const open = menu => menu.classList.contains('docs-dropdown-open');

test('the help button opens and closes its documentation menu', () => {
    const p = page('complete');
    const {button, menu} = p.headers[0];
    assert.equal(open(menu), false);
    button.click();
    assert.equal(open(menu), true, 'a click on ? opens the menu');
    button.click();
    assert.equal(open(menu), false, 'a second click closes it');
});

test('a click outside an open menu closes it; a click inside keeps it open', () => {
    const p = page('complete');
    const {button, menu, link} = p.headers[0];
    button.click();
    link.click();
    assert.equal(open(menu), true, 'choosing a link happens inside the dropdown');
    p.outside.click();
    assert.equal(open(menu), false, 'a click elsewhere on the page closes it');
    p.outside.click();
    assert.equal(open(menu), false, 'an outside click never opens it');
});

test('each dropdown toggles only its own menu', () => {
    const p = page('complete', 2);
    const [first, second] = p.headers;
    first.button.click();
    assert.deepEqual([open(first.menu), open(second.menu)], [true, false]);
    second.button.click();
    assert.deepEqual([open(first.menu), open(second.menu)], [false, true],
        'opening one menu closes the other, as an outside click');
});

test('loaded before the document is parsed, it binds on DOMContentLoaded', () => {
    const p = page('loading');
    const {button, menu} = p.headers[0];
    button.click();
    assert.equal(open(menu), false, 'nothing is bound before the DOM is ready');
    p.ready();
    button.click();
    assert.equal(open(menu), true);
    p.outside.click();
    assert.equal(open(menu), false);
});

test('a help button without a menu after it is ignored', () => {
    const p = page('complete');
    const {dropdown, button, menu} = p.headers[0];
    dropdown.children.splice(dropdown.children.indexOf(menu), 1);
    assert.doesNotThrow(() => button.click());
});

test('the pages load the shipped file and keep no inline dropdown code', () => {
    for (const name of ['index.html', 'admin.html']) {
        const html = fs.readFileSync(path.join(root, 'src/sigrift/bridge/templates', name), 'utf8');
        assert.match(html, /<script src="\{\{ url_for\('static', path='docs_dropdown\.js'\) \}\}\?v=\d+"><\/script>/, name);
        assert.match(html, /<button class="help-icon"[^>]*>\?<\/button>/, name);
        assert.doesNotMatch(html, /onclick=/, name);
        assert.doesNotMatch(html, /docs-dropdown-open'\)/, `${name}: the toggle is not inline`);
    }
});
