/* The shipped admin console (templates/admin.html with auth_guard.js, severity.js,
 * html_text.js, admin.js and crypto_admin.js, in that page order) in a stub DOM:
 * markup the shipped code writes is parsed by a real HTML parser (parse5) and
 * serialised like a browser does, so escaping, attribute values and injected
 * elements are read as a browser would build them. Requests go to a recording
 * fake network that answers with real fetch Response objects.
 *
 * Shared by the admin console suites: admin_console_security, admin_console_shell
 * and the admin_*_tab(s) suites.
 */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const util = require('node:util');
const vm = require('node:vm');
const parse5 = require('parse5');

const root = path.resolve(__dirname, '../../..');
const bridge = path.join(root, 'src/sigrift/bridge');
const SCRIPTS = ['auth_guard.js', 'severity.js', 'html_text.js', 'admin.js', 'crypto_admin.js']
    .map(name => path.join(bridge, 'static', name));
/* Every script admin.html loads, in its order, but panel_help.js (help popovers):
 * pass it as adminPage({ scripts: PAGE_SCRIPTS }) to test training.js,
 * protocol_admin.js and scorer_weights.js too. */
const PAGE_SCRIPTS = ['chart_utils.js', 'auth_guard.js', 'severity.js', 'html_text.js', 'admin.js', 'training.js',
    'protocol_admin.js', 'crypto_admin.js', 'scorer_weights.js'].map(name => path.join(bridge, 'static', name));
const SOURCES = new Map([...SCRIPTS, ...PAGE_SCRIPTS].map(file => [file, fs.readFileSync(file, 'utf8')]));
const TEMPLATE = parse5.parse(fs.readFileSync(path.join(bridge, 'templates/admin.html'), 'utf8'));

/* ------------------------------------------------------------------ */
/* Stub DOM                                                            */
/* ------------------------------------------------------------------ */

const NS = 'http://www.w3.org/1999/xhtml';
const VOID = new Set(['area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'source', 'track', 'wbr']);
const RAW_TEXT = new Set(['style', 'script', 'xmp', 'iframe', 'noembed', 'noframes', 'plaintext']);
const CONTROLS = new Set(['button', 'input', 'select', 'textarea']);

/* The HTML fragment serialisation algorithm's escaping. */
const escapeText = s => s.replace(/&/g, '&amp;').replace(/\u00a0/g, '&nbsp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const escapeAttr = s => s.replace(/&/g, '&amp;').replace(/\u00a0/g, '&nbsp;').replace(/"/g, '&quot;')
    .replace(/</g, '&lt;').replace(/>/g, '&gt;');

class FakeEvent {
    constructor(type, init = {}) {
        Object.assign(this, { bubbles: true }, init);
        this.type = type; this.defaultPrevented = false; this.stopped = false;
    }
    preventDefault() { this.defaultPrevented = true; }
    stopPropagation() { this.stopped = true; }
}

/* A node's links to the tree are not enumerable: a failing assertion inspects
 * its values without custom inspectors, and must not walk the whole page. */
function hide(node, values) {
    for (const [name, value] of Object.entries(values)) Object.defineProperty(node, name, { value, writable: true });
}

class FakeNode {
    constructor(doc) { hide(this, { ownerDocument: doc, parentNode: null, childNodes: [], listeners: {} }); }
    get firstChild() { return this.childNodes[0] || null; }
    get children() { return this.childNodes.filter(node => node.nodeType === 1); }
    get parentElement() { return this.parentNode && this.parentNode.nodeType === 1 ? this.parentNode : null; }
    get textContent() { return this.childNodes.map(node => node.textContent).join(''); }
    set textContent(value) {
        this.replaceChildren(...(value == null || value === '' ? [] : [new FakeText(this.ownerDocument, String(value))]));
    }
    appendChild(child) {
        if (child.parentNode) child.parentNode.removeChild(child);
        child.parentNode = this;
        this.childNodes.push(child);
        this.ownerDocument.mutated(this, 'childList', { addedNodes: [child], removedNodes: [] });
        return child;
    }
    removeChild(child) {
        const at = this.childNodes.indexOf(child);
        if (at < 0) throw new Error('NotFoundError: the node to remove is not a child of this node');
        this.childNodes.splice(at, 1);
        child.parentNode = null;
        this.ownerDocument.mutated(this, 'childList', { addedNodes: [], removedNodes: [child] });
        return child;
    }
    replaceChildren(...nodes) {
        const removed = this.childNodes;
        for (const node of removed) node.parentNode = null;
        this.childNodes = [];
        for (const node of nodes) { node.parentNode = this; this.childNodes.push(node); }
        this.ownerDocument.mutated(this, 'childList', { addedNodes: nodes, removedNodes: removed });
    }
    remove() { if (this.parentNode) this.parentNode.removeChild(this); }
    /* Keep assertion messages short: a node's inspection would walk the page. */
    [util.inspect.custom]() { return this.nodeType === 1 ? '<' + this.localName + (this.id ? '#' + this.id : '') + '>' : this.nodeName; }
    contains(node) { for (let n = node; n; n = n.parentNode) if (n === this) return true; return false; }
    addEventListener(type, listener) { (this.listeners[type] ||= []).push(listener); }
    removeEventListener(type, listener) {
        this.listeners[type] = this.listeners[type].filter(fn => fn !== listener);
    }
    dispatchEvent(event) {
        event.target ||= this;
        for (let node = this; node; node = node.parentNode) {
            event.currentTarget = node;
            for (const listener of [...(node.listeners[event.type] || [])]) listener.call(node, event);
            if (event.stopped || !event.bubbles) break;
        }
        return !event.defaultPrevented;
    }
}

class FakeText extends FakeNode {
    constructor(doc, data) { super(doc); this.nodeType = 3; this.nodeName = '#text'; this.data = data; }
    get textContent() { return this.data; }
    set textContent(value) { this.data = String(value); }
}

class FakeComment extends FakeNode {
    constructor(doc, data) { super(doc); this.nodeType = 8; this.nodeName = '#comment'; this.data = data; }
    get textContent() { return ''; }
}

function makeStyle(element) {
    let values = {};
    const load = text => {
        values = {};
        for (const declaration of String(text).split(';')) {
            const at = declaration.indexOf(':');
            if (at < 0) continue;
            const name = declaration.slice(0, at).trim().replace(/-([a-z])/g, (_, c) => c.toUpperCase());
            if (name) values[name] = declaration.slice(at + 1).trim();
        }
    };
    return new Proxy({}, {
        get(_, key) { return key === 'load' ? load : values[key] ?? ''; },
        set(_, key, value) {
            if (key === 'cssText') load(value); else values[key] = String(value);
            element.ownerDocument.mutated(element, 'attributes', { attributeName: 'style' });
            return true;
        },
    });
}

class FakeElement extends FakeNode {
    constructor(doc, tagName, attrs = []) {
        super(doc);
        this.nodeType = 1;
        this.localName = tagName.toLowerCase();
        this.tagName = this.nodeName = this.localName.toUpperCase();
        hide(this, { attrs: new Map(attrs.map(attr => [attr.name, attr.value])) });
        hide(this, { style: makeStyle(this) });
        if (this.attrs.has('style')) this.style.load(this.attrs.get('style'));
    }
    getAttribute(name) { name = name.toLowerCase(); return this.attrs.has(name) ? this.attrs.get(name) : null; }
    hasAttribute(name) { return this.attrs.has(name.toLowerCase()); }
    setAttribute(name, value) {
        name = name.toLowerCase();
        this.attrs.set(name, String(value));
        this.ownerDocument.mutated(this, 'attributes', { attributeName: name });
    }
    removeAttribute(name) {
        this.attrs.delete(name.toLowerCase());
        this.ownerDocument.mutated(this, 'attributes', { attributeName: name.toLowerCase() });
    }
    get attributes() { return [...this.attrs].map(([name, value]) => ({ name, value })); }
    /* data-* attributes, as element.dataset reads and writes them. */
    get dataset() {
        const attribute = key => 'data-' + String(key).replace(/[A-Z]/g, c => '-' + c.toLowerCase());
        return new Proxy({}, {
            get: (_, key) => (typeof key === 'string' && this.hasAttribute(attribute(key)) ? this.getAttribute(attribute(key)) : undefined),
            set: (_, key, value) => { this.setAttribute(attribute(key), value); return true; },
        });
    }
    get id() { return this.getAttribute('id') || ''; }
    set id(value) { this.setAttribute('id', value); }
    get className() { return this.getAttribute('class') || ''; }
    set className(value) { this.setAttribute('class', value); }
    get classList() {
        const names = () => this.className.split(/\s+/).filter(Boolean);
        return {
            contains: name => names().includes(name),
            add: (...add) => { this.className = [...new Set([...names(), ...add])].join(' '); },
            remove: (...drop) => { this.className = names().filter(name => !drop.includes(name)).join(' '); },
            toggle: name => {
                const on = !names().includes(name);
                this.className = (on ? [...names(), name] : names().filter(n => n !== name)).join(' ');
                return on;
            },
        };
    }
    get disabled() { return this.hasAttribute('disabled'); }
    set disabled(value) { if (value) this.setAttribute('disabled', ''); else this.removeAttribute('disabled'); }
    get type() { return this.getAttribute('type') || (this.localName === 'button' ? 'submit' : 'text'); }
    set type(value) { this.setAttribute('type', value); }
    get href() { return this.getAttribute('href'); }
    set href(value) { this.setAttribute('href', value); }
    get download() { return this.getAttribute('download'); }
    set download(value) { this.setAttribute('download', value); }
    get checked() { return 'checkedness' in this ? this.checkedness : this.hasAttribute('checked'); }
    set checked(value) { this.checkedness = !!value; }
    /* An option's selectedness: its `selected` attribute until script sets
     * it, as in a browser. A <select multiple> is read option by option. */
    get selected() { return 'selectedness' in this ? this.selectedness : this.hasAttribute('selected'); }
    set selected(value) { this.selectedness = !!value; }
    get options() { return this.querySelectorAll('option'); }
    get value() {
        if (this.localName === 'select') {
            const options = this.options;
            if (this.chosen === null) return '';
            const chosen = options.includes(this.chosen) ? this.chosen
                : options.find(option => option.selected) || options[0];
            return chosen ? chosen.value : '';
        }
        if (this.localName === 'option') {
            const value = this.getAttribute('value');
            return value !== null ? value : this.textContent.replace(/\s+/g, ' ').trim();
        }
        if ('dirtyValue' in this) return this.dirtyValue;
        if (this.localName === 'textarea') return this.textContent;
        return this.getAttribute('value') || '';
    }
    set value(value) {
        value = value == null ? '' : String(value);
        if (this.localName === 'select') this.chosen = this.options.find(option => option.value === value) || null;
        else if (this.localName === 'option') this.setAttribute('value', value);
        else this.dirtyValue = value;
    }
    /* The floor-plan canvas: drawing calls are recorded in `drawn` as
     * [method, ...args], and style assignments as ['=property', value]. */
    get width() { return Number(this.getAttribute('width')); }
    get height() { return Number(this.getAttribute('height')); }
    getContext() {
        if (!this.drawn) hide(this, { drawn: [] });
        const drawn = this.drawn;
        return new Proxy({}, {
            get: (_, method) => (...args) => { drawn.push([method, ...args]); },
            set: (_, property, value) => { drawn.push(['=' + String(property), value]); return true; },
        });
    }
    getBoundingClientRect() { return { left: 0, top: 0, width: this.width, height: this.height }; }
    get innerHTML() { return this.childNodes.map(serialize).join(''); }
    set innerHTML(html) {
        const context = parse5.defaultTreeAdapter.createElement(this.localName, NS, []);
        this.replaceChildren(...parse5.parseFragment(context, String(html)).childNodes
            .map(node => convert(this.ownerDocument, node)).filter(Boolean));
    }
    get outerHTML() { return serialize(this); }
    querySelectorAll(selector) {
        const match = compile(selector);
        return descendants(this).filter(match);
    }
    querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
    matches(selector) { return compile(selector)(this); }
    closest(selector) {
        const match = compile(selector);
        for (let el = this; el && el.nodeType === 1; el = el.parentNode) if (match(el)) return el;
        return null;
    }
    click() {
        if (this.disabled && CONTROLS.has(this.localName)) return; // as browsers do
        this.dispatchEvent(new FakeEvent('click'));
    }
    focus() { this.ownerDocument.activeElement = this; }
    blur() { this.ownerDocument.activeElement = this.ownerDocument.body; }
    /* Selecting a field's text makes it what document.execCommand('copy') copies. */
    select() { this.ownerDocument.selection = this; }
}

function descendants(node, self = false) {
    const out = self && node.nodeType === 1 ? [node] : [];
    const walk = parent => { for (const child of parent.childNodes) if (child.nodeType === 1) { out.push(child); walk(child); } };
    walk(node);
    return out;
}

function serialize(node) {
    if (node.nodeType === 3) {
        const parent = node.parentNode;
        return parent && parent.nodeType === 1 && RAW_TEXT.has(parent.localName) ? node.data : escapeText(node.data);
    }
    if (node.nodeType === 8) return '<!--' + node.data + '-->';
    let html = '<' + node.localName;
    for (const [name, value] of node.attrs) html += ' ' + name + '="' + escapeAttr(value) + '"';
    html += '>';
    if (VOID.has(node.localName)) return html;
    return html + node.childNodes.map(serialize).join('') + '</' + node.localName + '>';
}

function convert(doc, node) {
    if (node.nodeName === '#text') return new FakeText(doc, node.value);
    if (node.nodeName === '#comment') return new FakeComment(doc, node.data);
    const element = new FakeElement(doc, node.tagName, node.attrs);
    for (const child of node.childNodes) {
        const converted = convert(doc, child);
        converted.parentNode = element;
        element.childNodes.push(converted);
    }
    return element;
}

/* Selectors: compound selectors (tag, #id, .class, [attr], [attr="v"],
 * :not(...), :checked, :last-child) joined by descendant or child combinators, in
 * lists. Anything else throws, so a selector this stub cannot match never passes
 * silently. */
function splitTop(text, separator) {
    const parts = [];
    let depth = 0, quote = null, current = '';
    for (const ch of text) {
        if (quote) { if (ch === quote) quote = null; }
        else if (ch === '"' || ch === "'") quote = ch;
        else if (ch === '[' || ch === '(') depth++;
        else if (ch === ']' || ch === ')') depth--;
        if (!quote && depth === 0 && ch === separator) { parts.push(current); current = ''; continue; }
        current += ch;
    }
    if (quote || depth) throw new SyntaxError('Invalid selector: ' + text);
    parts.push(current);
    return parts;
}

function parseCompound(text) {
    const compound = { tag: null, ids: [], classes: [], attrs: [], nots: [], checked: false, lastChild: false };
    let rest = text, m;
    if ((m = /^(\*|[a-zA-Z][\w-]*)/.exec(rest))) { if (m[1] !== '*') compound.tag = m[1].toLowerCase(); rest = rest.slice(m[0].length); }
    while (rest) {
        if ((m = /^#([\w-]+)/.exec(rest))) compound.ids.push(m[1]);
        else if ((m = /^\.([\w-]+)/.exec(rest))) compound.classes.push(m[1]);
        else if ((m = /^\[\s*([\w-]+)\s*(?:=\s*(?:"([^"]*)"|'([^']*)'|([\w-]+)))?\s*\]/.exec(rest))) {
            compound.attrs.push({ name: m[1].toLowerCase(), value: m[2] ?? m[3] ?? m[4] });
        } else if (rest.startsWith(':checked')) {
            compound.checked = true;
            m = [':checked'];
        } else if ((m = /^:last-child(?![\w-])/.exec(rest))) compound.lastChild = true;
        else if (rest.startsWith(':not(')) {
            const end = rest.indexOf(')');
            compound.nots.push(parseCompound(rest.slice(5, end)));
            m = [rest.slice(0, end + 1)];
        } else throw new SyntaxError('Unsupported selector: ' + text);
        rest = rest.slice(m[0].length);
    }
    return compound;
}

function parseComplex(text) {
    const chain = [];
    let buffer = '', depth = 0, quote = null, combinator = null;
    for (const ch of text.trim() + ' ') {
        if (quote) { if (ch === quote) quote = null; buffer += ch; continue; }
        if (ch === '"' || ch === "'") quote = ch;
        if (ch === '[' || ch === '(') depth++;
        if (ch === ']' || ch === ')') depth--;
        if (depth === 0 && (ch === ' ' || ch === '>')) {
            if (buffer) { chain.push({ compound: parseCompound(buffer), combinator }); buffer = ''; combinator = ' '; }
            if (ch === '>') combinator = '>';
            continue;
        }
        buffer += ch;
    }
    return chain;
}

function matchCompound(el, c) {
    return (!c.tag || el.localName === c.tag)
        && c.ids.every(id => el.getAttribute('id') === id)
        && c.classes.every(name => el.classList.contains(name))
        && c.attrs.every(a => el.hasAttribute(a.name) && (a.value === undefined || el.getAttribute(a.name) === a.value))
        && c.nots.every(n => !matchCompound(el, n))
        && (!c.checked || el.checked)
        && (!c.lastChild || (!!el.parentNode && el.parentNode.children.at(-1) === el));
}

function matchChain(el, chain, index) {
    if (!matchCompound(el, chain[index].compound)) return false;
    if (index === 0) return true;
    if (chain[index].combinator === '>') return !!el.parentElement && matchChain(el.parentElement, chain, index - 1);
    for (let p = el.parentElement; p; p = p.parentElement) if (matchChain(p, chain, index - 1)) return true;
    return false;
}

function compile(selector) {
    const chains = splitTop(selector, ',').map(parseComplex);
    return el => chains.some(chain => matchChain(el, chain, chain.length - 1));
}

class FakeDocument extends FakeNode {
    constructor(tree) {
        super(null);
        this.ownerDocument = this;
        this.nodeType = 9;
        this.nodeName = '#document';
        this.cookie = '';
        this.selection = null;
        this.observers = [];
        this.documentElement = convert(this, tree.childNodes.find(node => node.tagName === 'html'));
        this.documentElement.parentNode = this;
        this.childNodes = [this.documentElement];
        this.head = this.documentElement.children.find(el => el.localName === 'head');
        this.body = this.documentElement.children.find(el => el.localName === 'body');
        this.activeElement = this.body;
    }
    createElement(tagName) { return new FakeElement(this, tagName); }
    createTextNode(data) { return new FakeText(this, String(data)); }
    getElementById(id) { return descendants(this.documentElement, true).find(el => el.getAttribute('id') === id) || null; }
    querySelectorAll(selector) { const match = compile(selector); return descendants(this.documentElement, true).filter(match); }
    querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
    /* Observers of the target itself (the shipped code never observes a subtree). */
    mutated(target, type, record) {
        for (const { observer, target: watched, options } of this.observers) {
            if (watched !== target || !options[type]) continue;
            if (options.attributeFilter && !options.attributeFilter.includes(record.attributeName)) continue;
            observer.enqueue({ type, target, addedNodes: [], removedNodes: [], ...record });
        }
    }
}

/* MutationObserver delivering its records in a microtask, as browsers do. */
function observerClass(doc) {
    return class MutationObserver {
        constructor(callback) { this.callback = callback; this.records = []; }
        observe(target, options) { doc.observers.push({ observer: this, target, options }); }
        disconnect() { doc.observers = doc.observers.filter(entry => entry.observer !== this); this.records = []; }
        enqueue(record) {
            this.records.push(record);
            if (this.records.length > 1) return;
            queueMicrotask(() => {
                const records = this.records;
                this.records = [];
                if (records.length) this.callback(records, this);
            });
        }
    };
}

/* ------------------------------------------------------------------ */
/* The admin page                                                      */
/* ------------------------------------------------------------------ */

const NOW = Date.parse('2026-11-10T12:00:00Z');

/* The page's clock: it reads NOW until a test lets time pass with
 * page.advance(ms), which runs the timers and intervals due by then. */
function pageClock() {
    const clock = { now: NOW, pending: [], next: 1 };
    clock.Date = class extends Date {
        constructor(...args) { if (args.length) super(...args); else super(clock.now); }
        static now() { return clock.now; }
    };
    const schedule = (fn, ms, every) => {
        const delay = Math.max(0, Number(ms) || 0);
        const timer = { id: clock.next++, fn, due: clock.now + delay, every: every ? Math.max(1, delay) : 0 };
        clock.pending.push(timer);
        return timer.id;
    };
    const cancel = id => { clock.pending = clock.pending.filter(timer => timer.id !== id); };
    Object.assign(clock, {
        setTimeout: (fn, ms) => schedule(fn, ms, false), clearTimeout: cancel,
        setInterval: (fn, ms) => schedule(fn, ms, true), clearInterval: cancel,
        run(ms) {
            const end = clock.now + ms;
            for (;;) {
                const [timer] = clock.pending.filter(t => t.due <= end).sort((a, b) => a.due - b.due || a.id - b.id);
                if (!timer) break;
                clock.now = timer.due;
                if (timer.every) timer.due += timer.every; else cancel(timer.id);
                timer.fn();
            }
            clock.now = end;
        },
    });
    return clock;
}

const settle = async () => { for (let i = 0; i < 4; i++) await new Promise(resolve => setImmediate(resolve)); };

function reply(status = 200, body, headers = {}) {
    if (status === 204) return new Response(null, { status, headers });
    const json = body !== undefined && typeof body !== 'string';
    return new Response(json ? JSON.stringify(body) : (body ?? ''), {
        status, headers: { 'content-type': json ? 'application/json' : 'text/plain', ...headers },
    });
}

const DEFAULT_ROUTES = {
    'GET /api/admin/stats': () => reply(200, {}),
    'GET /api/auth/me': () => reply(200, {}),
    'GET /api/admin/keys': () => reply(200, []),
    'GET /api/ca/certs': () => reply(200, []),
};

/* A browser with the admin page open. `cookie` holds the CSRF cookie for a
 * cookie-mode session (the session cookie itself is HttpOnly). `clipboard`
 * is the Clipboard API's behaviour ('grant', 'refuse' or 'absent'); without
 * it, document.execCommand('copy') answers `execCommand` and records the
 * selected text, which a browser copies only from a field in the page.
 * `hash` is the URL fragment the page opens with (a tab deep link). `scripts`
 * is the page's scripts in load order: SCRIPTS by default, PAGE_SCRIPTS for all
 * of them. What the
 * page writes to the browser console is kept in `page.logged`; see
 * noUnexpectedConsoleErrors for what happens to its errors. */
async function adminPage({
    cookie = 'csrf_token=csrf-fixture', storage = {}, routes = {}, confirmAnswer = true, clipboard: access = 'grant', execCommand = true,
    hash = '', scripts = SCRIPTS,
} = {}) {
    const doc = new FakeDocument(TEMPLATE);
    doc.cookie = cookie;
    const store = new Map(Object.entries(storage));
    const clock = pageClock();
    const requests = [], redirects = [], clipboard = [], copies = [], blobs = [], alerts = [], confirms = [], logged = [];
    const table = { ...DEFAULT_ROUTES, ...routes };
    doc.execCommand = command => {
        const field = doc.selection;
        copies.push([command, field && doc.contains(field) ? field.value : null]);
        return execCommand;
    };
    const writeText = async text => {
        if (access === 'refuse') throw new Error('NotAllowedError');
        clipboard.push(text);
    };
    const context = {
        console: Object.fromEntries(['log', 'info', 'debug', 'warn', 'error'].map(level => [level, (...args) => logged.push([level, ...args])])),
        Date: clock.Date, Headers, FormData, Blob, Element: FakeElement, queueMicrotask,
        document: doc,
        MutationObserver: observerClass(doc),
        sessionStorage: {
            getItem: key => (store.has(key) ? store.get(key) : null),
            setItem: (key, value) => store.set(key, String(value)),
            removeItem: key => store.delete(key),
        },
        location: { hash, pathname: '/admin', replace: url => redirects.push(url) },
        addEventListener() {},  // window 'load' and 'resize': never fired here
        navigator: access === 'absent' ? {} : { clipboard: { writeText } },
        URL: { createObjectURL: blob => { blobs.push(blob); return 'blob:admin/' + blobs.length; }, revokeObjectURL() {} },
        setTimeout: clock.setTimeout, clearTimeout: clock.clearTimeout,
        setInterval: clock.setInterval, clearInterval: clock.clearInterval,
        alert: message => alerts.push(message),
        confirm: message => { confirms.push(message); return typeof confirmAnswer === 'function' ? confirmAnswer(message) : confirmAnswer; },
        fetch: async (url, options = {}) => {
            const method = (options.method || 'GET').toUpperCase();
            // Every body the console sends is JSON; anything else fails the test.
            const body = options.body === undefined ? undefined : JSON.parse(options.body);
            const request = { method, url, headers: { ...options.headers }, credentials: options.credentials, body };
            requests.push(request);
            const route = table[method + ' ' + url] || table[method + ' ' + url.split('?')[0]];
            return route ? route(request) : reply(404, { detail: 'Not Found' });
        },
    };
    context.window = context;
    vm.createContext(context);
    for (const file of scripts) vm.runInContext(SOURCES.get(file), context, { filename: file });
    doc.dispatchEvent(new FakeEvent('DOMContentLoaded', { bubbles: false }));
    await settle();

    const byId = id => doc.getElementById(id);
    let errorsAllowed = 0;
    const page = {
        doc, context, requests, redirects, clipboard, copies, blobs, alerts, confirms, logged, store, byId, routes: table,
        /* Console errors written since the last allowConsoleErrors(). */
        unexpectedConsoleErrors: () => logged.slice(errorsAllowed).filter(([level]) => level === 'error'),
        /* The test expects the page to have logged an error by now (a failure it also shows on the page). */
        allowConsoleErrors() { errorsAllowed = logged.length; },
        /* Requests that change state, as the server sees them. */
        writes: () => requests.filter(r => r.method !== 'GET'),
        toasts: () => byId('toast-container').children.map(el => ({ text: el.textContent, type: el.className.replace('toast toast-', ''), markup: el.children.length })),
        modal: () => doc.querySelector('.admin-modal-backdrop .admin-modal'),
        button(label, scope = page.modal()) {
            const found = scope.querySelectorAll('button').find(b => b.textContent.trim() === label);
            assert.ok(found, 'no button labelled ' + JSON.stringify(label));
            return found;
        },
        async click(el) { el.click(); await settle(); },
        async tab(name) { await page.click(doc.querySelector('[data-tab="' + name + '"]')); },
        async key(key, target = doc) { target.dispatchEvent(new FakeEvent('keydown', { key })); await settle(); },
        async input(el, value) { el.value = value; el.dispatchEvent(new FakeEvent('input')); await settle(); },
        async change(el, value) { el.value = value; el.dispatchEvent(new FakeEvent('change')); await settle(); },
        /* Ticks the reveal dialog's "I have stored this key" box. */
        async acknowledge(checked) {
            const box = page.modal().querySelector('#admin-rawkey-ack');
            box.checked = checked;
            box.dispatchEvent(new FakeEvent('change'));
            await settle();
        },
        /* Lets `ms` of time pass: the timers and intervals due by then run. */
        async advance(ms) { clock.run(ms); await settle(); },
        /* The requests that opening the `name` tab sends. */
        async opens(name) {
            const before = requests.length;
            await page.tab(name);
            return requests.slice(before).map(r => r.method + ' ' + r.url);
        },
    };
    openPages.push(page);
    return page;
}

/* Pages opened by the test that is running. The console's own error paths
 * (a swallowed exception in a render, the toast fallback) only reach
 * console.error, so a suite runs `test.afterEach(noUnexpectedConsoleErrors)`:
 * an error the test did not allow with page.allowConsoleErrors() fails it. */
const openPages = [];
function noUnexpectedConsoleErrors() {
    const errors = openPages.splice(0).flatMap(page => page.unexpectedConsoleErrors())
        .map(([, ...args]) => args.map(arg => (arg instanceof Error || (arg && arg.stack) ? String(arg.stack || arg) : String(arg))).join(' '));
    assert.deepEqual(errors, [], 'the admin page logged an error the test did not expect');
}

/* The credentials a request carries, as the server reads them. */
const credentialHeaders = request => Object.fromEntries(['X-API-Key', 'X-Session-Token', 'X-CSRF-Token']
    .filter(name => request.headers[name] !== undefined).map(name => [name, request.headers[name]]));

/* Controls that read or dismiss but change nothing, so a locked console
 * may leave them enabled. Every other button on the page is an action. */
const READ_ONLY_CONTROLS = ['.help-icon', '#admin-auth-retry', '#audit-detail-close', '#audit-detail-copy', '#audit-detail-dismiss',
    '#node-detail-close', '#node-detail-dismiss'].join(', ');

/* Markup no server string may introduce: elements that run script or load
 * resources, any inline event handler, and javascript: URLs. */
const ACTIVE = new Set(['script', 'img', 'svg', 'iframe', 'object', 'embed', 'math', 'style', 'link', 'meta', 'base', 'form', 'video', 'audio']);
function assertInert(container, label = 'rendered markup') {
    assert.ok(container, label + ' exists');
    for (const el of descendants(container, true)) {
        assert.ok(!ACTIVE.has(el.localName), label + ' contains an injected <' + el.localName + '>');
        for (const { name, value } of el.attributes) {
            assert.ok(!name.startsWith('on'), label + ' has an injected ' + name + ' attribute on <' + el.localName + '>');
            assert.ok(!/^\s*javascript:/i.test(value), label + ' has a javascript: URL');
        }
    }
}

/* Server-provided strings: markup for text positions, and markup without
 * double quotes for values the page writes into double-quoted attributes. */
const MARKUP = '<img src=x onerror="alert(1)"><script>alert(2)</script>&amp; \'single\' "double"';
const ATTR_MARKUP = '<b onmouseover=alert(3)>id&amp;</b>';

const CSRF = 'csrf-fixture';

/* A cookie-mode change: the CSRF cookie from auth_guard's fetch wrapper,
 * same-origin credentials, and no header credentials. */
function assertCookieWrite(request, { json = true } = {}) {
    const label = request.method + ' ' + request.url;
    assert.equal(request.headers['X-CSRF-Token'], CSRF, label + ' carries the CSRF cookie');
    assert.equal(request.credentials, 'same-origin', label + ' sends same-origin credentials');
    assert.equal(request.headers['X-API-Key'], undefined, label);
    assert.equal(request.headers['X-Session-Token'], undefined, label);
    assert.equal(request.headers.Accept, 'application/json', label);
    if (json) assert.equal(request.headers['Content-Type'], 'application/json', label + ' declares its JSON body');
}

const call = request => [request.method, request.url, request.body];
const cell = (row, label) => row.querySelector('[data-label="' + label + '"]');

module.exports = {
    adminPage, noUnexpectedConsoleErrors, reply, settle, FakeEvent, credentialHeaders, READ_ONLY_CONTROLS, assertInert,
    MARKUP, ATTR_MARKUP, CSRF, assertCookieWrite, call, cell, escapeText, SCRIPTS, PAGE_SCRIPTS,
};
