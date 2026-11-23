/* A small, faithful-enough DOM for running the shipped dashboard scripts in
 * node:vm. innerHTML is parsed by parse5 (the WHATWG HTML parser) and read
 * back with the HTML fragment serialization rules, so a helper that escapes
 * by writing a text node and reading innerHTML behaves exactly as in a
 * browser: text escapes & < > and NBSP, attribute values escape & " and NBSP.
 * Tests then inspect the parsed tree, which is what a browser would build.
 */
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const parse5 = require('parse5');

const STATIC = path.resolve(__dirname, '../../../src/sigrift/bridge/static');
const INDEX_TEMPLATE = path.resolve(__dirname, '../../../src/sigrift/bridge/templates/index.html');
const VOID = new Set(['area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'source', 'track', 'wbr']);
const RAW_TEXT = new Set(['style', 'script', 'xmp', 'iframe', 'noembed', 'noframes', 'plaintext']);

function escapeText(value, attribute) {
    let out = String(value).replace(/&/g, '&amp;').replace(/\u00a0/g, '&nbsp;');
    return attribute ? out.replace(/"/g, '&quot;') : out.replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

/* -- Selectors: tag, *, #id, .class, [attr], [attr(=|^=|$=|*=|~=)value],
 *    :not(compound), descendant and child combinators, comma lists. ---- */
function parseCompound(text) {
    const parts = [];
    let rest = text;
    while (rest.length) {
        let m;
        if ((m = /^(\*|[a-zA-Z][\w-]*)/.exec(rest))) parts.push({ kind: 'tag', name: m[1].toLowerCase() });
        else if ((m = /^#([\w-]+)/.exec(rest))) parts.push({ kind: 'id', name: m[1] });
        else if ((m = /^\.([\w-]+)/.exec(rest))) parts.push({ kind: 'class', name: m[1] });
        else if ((m = /^\[\s*([\w-]+)\s*(?:([\^$*~]?=)\s*(?:"([^"]*)"|'([^']*)'|([^\]\s]+)))?\s*\]/.exec(rest))) {
            parts.push({ kind: 'attr', name: m[1].toLowerCase(), op: m[2], value: m[3] ?? m[4] ?? m[5] });
        } else if ((m = /^:not\(([^)]*)\)/.exec(rest))) parts.push({ kind: 'not', inner: parseCompound(m[1].trim()) });
        else throw new SyntaxError(`Unsupported selector: ${text}`);
        rest = rest.slice(m[0].length);
    }
    return parts;
}
/* Split at top-level commas, whitespace and '>' only: never inside [...],
 * (...) or a quoted attribute value such as [data-node="edge 1"]. */
function selectorTokens(selector) {
    const alternatives = [[]];
    let depth = 0, quote = null, current = '';
    const flush = () => { if (current) alternatives.at(-1).push(current); current = ''; };
    for (const ch of selector) {
        if (quote) { current += ch; if (ch === quote) quote = null; continue; }
        if (ch === '"' || ch === "'") { quote = ch; current += ch; continue; }
        if (ch === '[' || ch === '(') depth++;
        else if (ch === ']' || ch === ')') depth--;
        if (depth) { current += ch; continue; }
        if (ch === ',') { flush(); alternatives.push([]); }
        else if (/\s/.test(ch)) flush();
        else if (ch === '>') { flush(); alternatives.at(-1).push('>'); }
        else current += ch;
    }
    flush();
    return alternatives;
}
function parseSelector(selector) {
    return selectorTokens(selector).map(tokens => {
        const steps = [];
        let combinator = ' ';
        for (const token of tokens) {
            if (token === '>') { combinator = '>'; continue; }
            steps.push({ combinator, parts: parseCompound(token) });
            combinator = ' ';
        }
        return steps;
    });
}
function matchesCompound(el, parts) {
    return parts.every(part => {
        switch (part.kind) {
            case 'tag': return part.name === '*' || el.localName === part.name;
            case 'id': return el.getAttribute('id') === part.name;
            case 'class': return el.classList.contains(part.name);
            case 'not': return !matchesCompound(el, part.inner);
            default: {
                const value = el.getAttribute(part.name);
                if (value == null) return false;
                if (!part.op) return true;
                if (part.op === '=') return value === part.value;
                if (part.op === '^=') return value.startsWith(part.value);
                if (part.op === '$=') return value.endsWith(part.value);
                if (part.op === '*=') return value.includes(part.value);
                return value.split(/\s+/).includes(part.value);
            }
        }
    });
}
function matchesSteps(el, steps, index) {
    if (!matchesCompound(el, steps[index].parts)) return false;
    if (index === 0) return true;
    let ancestor = el.parentNode;
    if (steps[index].combinator === '>') return !!ancestor && ancestor.nodeType === 1 && matchesSteps(ancestor, steps, index - 1);
    for (; ancestor && ancestor.nodeType === 1; ancestor = ancestor.parentNode) {
        if (matchesSteps(ancestor, steps, index - 1)) return true;
    }
    return false;
}

class Event {
    constructor(type, init = {}) {
        Object.assign(this, init);
        this.type = type;
        this.defaultPrevented = false;
        this._stopped = false;
    }
    preventDefault() { this.defaultPrevented = true; }
    stopPropagation() { this._stopped = true; }
}

class Node {
    constructor(doc) { this.ownerDocument = doc; this.parentNode = null; this.childNodes = []; }
    get firstChild() { return this.childNodes[0] || null; }
    hasChildNodes() { return this.childNodes.length > 0; }
    get parentElement() { return this.parentNode && this.parentNode.nodeType === 1 ? this.parentNode : null; }
    get children() { return this.childNodes.filter(child => child.nodeType === 1); }
    appendChild(child) {
        if (child.parentNode) child.parentNode.removeChild(child);
        this.childNodes.push(child); child.parentNode = this; return child;
    }
    removeChild(child) {
        const index = this.childNodes.indexOf(child);
        if (index !== -1) { this.childNodes.splice(index, 1); child.parentNode = null; }
        return child;
    }
    /* select.remove(index) drops that option, as HTMLSelectElement does;
     * any other remove() takes the node out of its parent. */
    remove(index) {
        if (this.localName === 'select' && arguments.length) { const option = this.options[index]; if (option) option.remove(); return; }
        if (this.parentNode) this.parentNode.removeChild(this);
    }
    contains(node) { for (; node; node = node.parentNode) if (node === this) return true; return false; }
    get textContent() { return this.childNodes.map(child => child.textContent).join(''); }
    set textContent(value) {
        for (const child of this.childNodes) child.parentNode = null;
        this.childNodes = [];
        if (value !== '' && value != null) this.appendChild(new Text(this.ownerDocument, String(value)));
    }
}

class Text extends Node {
    constructor(doc, value) { super(doc); this.nodeType = 3; this.data = value; }
    get textContent() { return this.data; }
    set textContent(value) { this.data = String(value); }
}

class Element extends Node {
    constructor(doc, tag) {
        super(doc);
        this.nodeType = 1;
        this.localName = tag.toLowerCase();
        this.tagName = this.localName.toUpperCase();
        this.nodeName = this.tagName;
        this._attrs = new Map();
        this._listeners = {};
        this.style = {};
        this.dataset = {};
        this.disabled = false;
        this.checked = false;
        this.hidden = false;
        this.scrollTop = 0; this.scrollHeight = 0; this.clientHeight = 0; this.clientWidth = 0;
        this.width = 300; this.height = 150;
        const el = this;
        this.classList = {
            add: (...names) => el._setClasses([...el._classes(), ...names]),
            remove: (...names) => el._setClasses(el._classes().filter(name => !names.includes(name))),
            contains: name => el._classes().includes(name),
            toggle(name, force) {
                const on = force === undefined ? !this.contains(name) : !!force;
                if (on) this.add(name); else this.remove(name);
                return on;
            },
        };
    }
    _classes() { return (this.getAttribute('class') || '').split(/\s+/).filter(Boolean); }
    _setClasses(names) { this.setAttribute('class', [...new Set(names)].join(' ')); }
    get id() { return this.getAttribute('id') || ''; }
    set id(value) { this.setAttribute('id', value); }
    get className() { return this.getAttribute('class') || ''; }
    set className(value) { this.setAttribute('class', value); }
    get title() { return this.getAttribute('title') || ''; }
    set title(value) { this.setAttribute('title', value); }
    /* A <select> can only hold one of its options, as in a browser: setting a
     * value no option has selects nothing (value ''), until the option list
     * changes; replacing the options resets to the default selection. */
    get value() {
        if (this.localName === 'select') {
            const options = this.options;
            if (this._selectedOption && options.includes(this._selectedOption)) return this._selectedOption.value;
            if (this._unmatchedOptions && this._unmatchedOptions.length === options.length
                && this._unmatchedOptions.every((option, index) => option === options[index])) return '';
            const selected = options.find(option => option.hasAttribute('selected')) || options[0];
            return selected ? selected.value : '';
        }
        if (this._value !== undefined) return this._value;
        if (this.localName === 'option') return this.getAttribute('value') ?? this.textContent;
        return this.getAttribute('value') ?? '';
    }
    set value(value) {
        if (this.localName === 'select') {
            const options = this.options;
            this._selectedOption = options.find(option => option.value === String(value)) || null;
            this._unmatchedOptions = this._selectedOption ? null : options;
            return;
        }
        this._value = String(value);
    }
    get options() { return this.querySelectorAll('option'); }
    get attributes() { return [...this._attrs].map(([name, value]) => ({ name, value })); }
    getAttribute(name) { name = String(name).toLowerCase(); return this._attrs.has(name) ? this._attrs.get(name) : null; }
    setAttribute(name, value) {
        name = String(name).toLowerCase();
        this._attrs.set(name, String(value));
        if (name === 'style') {     // inline declarations populate element.style, as in a browser
            for (const declaration of String(value).split(';')) {
                const [property, ...rest] = declaration.split(':');
                if (!property.trim() || !rest.length) continue;
                this.style[property.trim().replace(/-([a-z])/g, (_, c) => c.toUpperCase())] = rest.join(':').trim();
            }
        }
    }
    hasAttribute(name) { return this._attrs.has(String(name).toLowerCase()); }
    removeAttribute(name) { this._attrs.delete(String(name).toLowerCase()); }
    get offsetParent() { return this.parentNode; }
    get innerHTML() {
        return this.childNodes.map(child => serialize(child, RAW_TEXT.has(this.localName))).join('');
    }
    set innerHTML(html) {
        for (const child of this.childNodes) child.parentNode = null;
        this.childNodes = [];
        const fragment = parse5.parseFragment(String(html));
        for (const node of fragment.childNodes) {
            const converted = convert(this.ownerDocument, node);
            if (converted) this.appendChild(converted);
        }
    }
    querySelectorAll(selector) {
        const alternatives = parseSelector(selector), out = [];
        (function walk(node) {
            for (const child of node.children) {
                if (alternatives.some(steps => matchesSteps(child, steps, steps.length - 1))) out.push(child);
                walk(child);
            }
        })(this);
        return out;
    }
    querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
    matches(selector) { return parseSelector(selector).some(steps => matchesSteps(this, steps, steps.length - 1)); }
    closest(selector) {
        for (let node = this; node && node.nodeType === 1; node = node.parentNode) if (node.matches(selector)) return node;
        return null;
    }
    addEventListener(type, fn) { (this._listeners[type] ||= []).push(fn); }
    removeEventListener(type, fn) {
        const list = this._listeners[type] || [];
        if (list.includes(fn)) list.splice(list.indexOf(fn), 1);
    }
    dispatchEvent(event) {
        if (!event.target) event.target = this;
        for (let node = this; node && !event._stopped; node = node.parentNode) {
            event.currentTarget = node;
            for (const fn of [...((node._listeners || {})[event.type] || [])]) fn.call(node, event);
            const property = node['on' + event.type];
            if (typeof property === 'function') property.call(node, event);
        }
        return !event.defaultPrevented;
    }
    click() { if (!this.disabled) this.dispatchEvent(new Event('click', { bubbles: true })); }
    focus() { this.ownerDocument.activeElement = this; }
    blur() { if (this.ownerDocument.activeElement === this) this.ownerDocument.activeElement = this.ownerDocument.body; }
    select() {}
    scrollIntoView() { this.scrolledIntoView = true; }
    getBoundingClientRect() { return { left: 0, top: 0, width: this.width, height: this.height }; }
    getContext() { return new Proxy({}, { get: (target, key) => (key in target ? target[key] : () => ({ addColorStop() {} })), set: (target, key, value) => { target[key] = value; return true; } }); }
}

function serialize(node, raw) {
    if (node.nodeType === 3) return raw ? node.data : escapeText(node.data, false);
    if (node.nodeType !== 1) return '';
    const attrs = node.attributes.map(({ name, value }) => ` ${name}="${escapeText(value, true)}"`).join('');
    if (VOID.has(node.localName)) return `<${node.localName}${attrs}>`;
    return `<${node.localName}${attrs}>${node.innerHTML}</${node.localName}>`;
}

function convert(doc, node) {
    if (node.nodeName === '#text') return new Text(doc, node.value);
    if (!node.tagName) return null;
    const el = new Element(doc, node.tagName);
    for (const attr of node.attrs) el.setAttribute(attr.name, attr.value);
    const children = node.tagName === 'template' ? node.content.childNodes : node.childNodes;
    for (const child of children) {
        const converted = convert(doc, child);
        if (converted) el.appendChild(converted);
    }
    return el;
}

/* Elements with an id in the shipped dashboard page, so a test drives the
 * controls an operator has: the real tag, attributes, default values and the
 * <option>s a <select> offers. */
let templateIds = null;
function templateNode(id) {
    if (!templateIds) {
        templateIds = new Map();
        (function walk(node) {
            for (const child of node.childNodes || []) {
                if (!child.tagName) continue;
                const attr = child.attrs.find(a => a.name === 'id');
                if (attr && !templateIds.has(attr.value)) templateIds.set(attr.value, child);
                walk(child.tagName === 'template' ? child.content : child);
            }
        })(parse5.parse(fs.readFileSync(INDEX_TEMPLATE, 'utf8')));
    }
    return templateIds.get(id) || null;
}
/* The element alone: its attributes, plus its options (a select) or its
 * text (an element with no child elements). Nested id'd elements are created
 * separately by the test, so no subtree is copied. */
function fromTemplate(doc, node) {
    const el = new Element(doc, node.tagName);
    for (const attr of node.attrs) el.setAttribute(attr.name, attr.value);
    el.hidden = el.hasAttribute('hidden');
    el.disabled = el.hasAttribute('disabled');
    el.checked = el.hasAttribute('checked');
    const elementChildren = node.childNodes.filter(child => child.tagName);
    if (node.tagName === 'select' || !elementChildren.length) {
        for (const child of node.childNodes) {
            const converted = convert(doc, child);
            if (converted) el.appendChild(converted);
        }
    }
    return el;
}
/* Give the element `id` the subtree index.html defines for it, e.g. a
 * button group or a whole panel: elements the test also listed move into
 * their place, and every other element is built from the page. */
function fillFromTemplate(doc, id) {
    const root = doc.getElementById(id), node = templateNode(id);
    if (!root || !node) throw new Error(`#${id} must be listed, and defined by index.html`);
    (function fill(parent, source) {
        if (source.tagName === 'select' || parent.children.length || !source.childNodes.some(child => child.tagName)) return;
        for (const child of source.childNodes) {
            if (child.nodeName === '#text') { parent.appendChild(new Text(doc, child.value)); continue; }
            if (!child.tagName) continue;
            const childId = child.attrs.find(attr => attr.name === 'id');
            const el = (childId && doc.getElementById(childId.value)) || fromTemplate(doc, child);
            parent.appendChild(el);
            fill(el, child.tagName === 'template' ? child.content : child);
        }
    })(root, node);
}

class Document {
    constructor() {
        this.nodeType = 9;
        this.cookie = '';
        this.title = 'SigRift';
        this.hidden = false;
        this.visibilityState = 'visible';
        this._listeners = {};
        this.documentElement = new Element(this, 'html');
        this.body = new Element(this, 'body');
        this.documentElement.appendChild(this.body);
        this.activeElement = this.body;
    }
    createElement(tag) { return new Element(this, tag); }
    createTextNode(value) { return new Text(this, String(value)); }
    getElementById(id) {
        return this.documentElement.querySelectorAll('[id]').find(el => el.getAttribute('id') === String(id)) || null;
    }
    querySelectorAll(selector) { return this.documentElement.querySelectorAll(selector); }
    querySelector(selector) { return this.documentElement.querySelector(selector); }
    addEventListener(type, fn) { (this._listeners[type] ||= []).push(fn); }
    removeEventListener(type, fn) {
        const list = this._listeners[type] || [];
        if (list.includes(fn)) list.splice(list.indexOf(fn), 1);
    }
    dispatchEvent(event) {
        for (const fn of [...(this._listeners[event.type] || [])]) fn.call(this, event);
        return !event.defaultPrevented;
    }
    execCommand() { return true; }
}

class Storage {
    constructor() { this._map = new Map(); }
    get length() { return this._map.size; }
    getItem(key) { return this._map.has(String(key)) ? this._map.get(String(key)) : null; }
    setItem(key, value) { this._map.set(String(key), String(value)); }
    removeItem(key) { this._map.delete(String(key)); }
    clear() { this._map.clear(); }
    key(index) { return [...this._map.keys()][index] ?? null; }
}

class Headers {
    constructor(init = {}) { this._map = new Map(Object.entries(init).map(([k, v]) => [k.toLowerCase(), String(v)])); }
    get(name) { return this._map.get(String(name).toLowerCase()) ?? null; }
    set(name, value) { this._map.set(String(name).toLowerCase(), String(value)); }
    has(name) { return this._map.has(String(name).toLowerCase()); }
}

function response(status, body, contentType = 'application/json') {
    const headers = new Headers(contentType ? { 'content-type': contentType } : {});
    return {
        status, ok: status >= 200 && status < 300, headers,
        json: async () => {
            if (typeof body === 'string') return JSON.parse(body);
            return JSON.parse(JSON.stringify(body));
        },
    };
}

/* Build a browser-like global for the shipped scripts.
 * `routes(url, options)` answers fetch; it may return a response(), a plain
 * value (sent as 200 JSON), an Error (network failure) or undefined ([]).
 */
function browser({ ids = [], cookie = '', routes = () => undefined, confirm = () => true, prompt = () => null, template = false } = {}) {
    const document = new Document();
    document.cookie = cookie;
    for (const id of ids) {
        const [tag, name] = id.includes(':') ? id.split(':') : [null, id];
        const node = template ? templateNode(name) : null;
        if (node && tag && node.tagName !== tag) throw new Error(`#${name} is a <${node.tagName}> in index.html, not a <${tag}>`);
        const el = node ? fromTemplate(document, node) : document.createElement(tag || 'div');
        el.id = name;
        document.body.appendChild(el);
    }
    const requests = [], sockets = [], timers = [], navigations = [], warnings = [], dialogs = [];
    let clock = 0, confirmFn = confirm, promptFn = prompt;
    function settleAnswer(answer) {
        if (answer instanceof Error) throw answer;
        if (answer && typeof answer === 'object' && 'status' in answer && 'headers' in answer) return answer;
        return response(200, answer === undefined ? [] : answer);
    }
    function fetch(url, options = {}) {
        const call = { url: String(url), options, method: (options.method || 'GET').toUpperCase(), headers: options.headers || {} };
        requests.push(call);
        try { return Promise.resolve(routes(call.url, options, call)).then(settleAnswer); }
        catch (error) { return Promise.reject(error); }
    }
    class WebSocket {
        constructor(url, protocols) {
            this.url = url; this.protocols = protocols; this.readyState = 0; this.closed = false;
            sockets.push(this);
        }
        open() { this.readyState = 1; if (this.onopen) this.onopen({}); }
        message(data) { if (this.onmessage) this.onmessage({ data: typeof data === 'string' ? data : JSON.stringify(data) }); }
        close() {
            if (this.closed) return;
            this.closed = true; this.readyState = 3;
            if (this.onclose) this.onclose({});
        }
    }
    function schedule(callback, delay, repeat) {
        const timer = { id: timers.length + 1, callback, delay: Number(delay) || 0, repeat, cleared: false };
        timer.at = clock + timer.delay;
        timers.push(timer);
        return timer.id;
    }
    function clear(id) { const timer = timers[id - 1]; if (timer) timer.cleared = true; }
    const location = {
        protocol: 'https:', host: 'bridge.test', hostname: 'bridge.test', origin: 'https://bridge.test', pathname: '/', search: '', href: 'https://bridge.test/',
        replace(url) { navigations.push(String(url)); },
        assign(url) { navigations.push(String(url)); },
    };
    const context = {
        document, location, navigator: {}, console: {
            log() {}, info() {}, debug() {}, error: (...args) => warnings.push(args.join(' ')), warn: (...args) => warnings.push(args.join(' ')),
        },
        fetch, WebSocket, Headers, Event, FormData: class FormData {},
        localStorage: new Storage(), sessionStorage: new Storage(),
        performance: { now: () => clock },
        setTimeout: (cb, delay) => schedule(cb, delay, false), clearTimeout: clear,
        setInterval: (cb, delay) => schedule(cb, delay, true), clearInterval: clear,
        requestAnimationFrame: cb => schedule(cb, 16, false),
        getComputedStyle: () => ({ getPropertyValue: () => '' }),
        confirm: message => { dialogs.push(['confirm', message]); return confirmFn(message); },
        alert: message => { dialogs.push(['alert', message]); },
        prompt: message => { dialogs.push(['prompt', message]); return promptFn(message); },
        open: url => { navigations.push('open:' + url); },
        addEventListener(type, fn) { (context._windowListeners[type] ||= []).push(fn); },
        _windowListeners: {},
        Promise, JSON, Math, Date, Object, Array, String, Number, Boolean, RegExp, Error, Map, Set, Proxy, parseInt, parseFloat, isNaN, encodeURIComponent, decodeURIComponent,
    };
    context.window = context;
    context.self = context;
    vm.createContext(context);
    return {
        context, document, requests, sockets, timers, navigations, warnings, dialogs,
        load(...names) {
            for (const name of names) {
                const filename = path.join(STATIC, name);
                vm.runInContext(fs.readFileSync(filename, 'utf8'), context, { filename });
            }
            return this;
        },
        el: id => document.getElementById(id),
        add(id, tag = 'div', parent = document.body) {
            const el = document.createElement(tag); el.id = id; parent.appendChild(el); return el;
        },
        advance(ms) { clock += ms; },
        answerConfirm(fn) { confirmFn = typeof fn === 'function' ? fn : () => fn; },
        answerPrompt(fn) { promptFn = typeof fn === 'function' ? fn : () => fn; },
        /* Mutating requests, in order. */
        writes: () => requests.filter(call => call.method !== 'GET'),
        /* Run pending timers once, in delay order (no wall clock involved). */
        runTimers(filter = () => true) {
            const due = timers.filter(timer => !timer.cleared && !timer.ran && filter(timer)).sort((a, b) => a.delay - b.delay);
            for (const timer of due) {
                if (!timer.repeat) timer.ran = true;
                timer.callback();
            }
            return due.length;
        },
        /* Let `ms` of simulated time pass: every timeout and interval that
         * falls due runs in time order, and fetch replies and other promise
         * work settle after each one, as they would between browser tasks. */
        async tick(ms) {
            const end = clock + ms;
            for (let fired = 0; ; fired++) {
                if (fired > 100000) throw new Error('timers keep rescheduling inside the window');
                const due = timers.filter(timer => !timer.cleared && !timer.ran && timer.at <= end)
                    .sort((a, b) => a.at - b.at || a.id - b.id)[0];
                if (!due) break;
                clock = Math.max(clock, due.at);
                if (due.repeat) due.at += Math.max(1, due.delay); else due.ran = true;
                due.callback();
                await settle(1);
            }
            clock = end;
            await settle();
        },
        fire(type, init = {}) { document.dispatchEvent(new Event(type, init)); },
    };
}

/* How login.js hands credentials to the dashboard today. Only these lines
 * know the storage keys, so the planned cookie-only change touches one place. */
const handoff = {
    sessionToken: (f, token) => f.context.sessionStorage.setItem('bridge_session_token', token),
    apiKey: (f, key) => f.context.sessionStorage.setItem('bridge_api_key', key),
};

/* Boot the shipped dashboard in index.html's script order (only the subset
 * these tests need): the auth guard, the dashboard and the given panel
 * scripts, then DOMContentLoaded. Each listed id that index.html defines is
 * built from the page itself; 'tag:id' names the tag the test expects.
 * Each listed id in `subtrees` also gets its index.html children. */
function bootDashboard({ ids = [], cookie = 'csrf_token=csrf-abc123', token = null, apiKey = null,
    routes = () => undefined, scripts = [], subtrees = [], session = {} } = {}) {
    const defaults = url => (url.startsWith('/api/auth/me') ? { username: 'op', display_name: 'Operator', role: 'admin' } : undefined);
    const f = browser({ template: true, ids: ['toast-container', 'button:logout-btn', ...ids], cookie, routes: (url, options, call) => {
        const answer = routes(url, options, call);
        return answer === undefined ? defaults(url) : answer;
    } });
    for (const id of subtrees) fillFromTemplate(f.document, id);
    // Every toast shown so far, including those that already timed out.
    const container = f.el('toast-container'), shown = [], append = container.appendChild.bind(container);
    container.appendChild = child => { shown.push(child.textContent); return append(child); };
    f.toasts = () => [...shown];
    if (token) handoff.sessionToken(f, token);
    if (apiKey) handoff.apiKey(f, apiKey);
    // `session` seeds sessionStorage, e.g. with what an earlier page load of this tab left there.
    for (const [key, value] of Object.entries(session)) f.context.sessionStorage.setItem(key, value);
    f.load('html_text.js', 'scanner_availability.js', 'auth_guard.js', 'dashboard.js', ...scripts);
    f.fire('DOMContentLoaded');
    f.db = f.context.dashboard;
    f.lastWrite = () => f.writes().at(-1);
    f.body = call => JSON.parse(call.options.body);
    return f;
}

/* Every element in a subtree (including the root's descendants). */
function elements(root) {
    const out = [];
    (function walk(node) { for (const child of node.children) { out.push(child); walk(child); } })(root);
    return out;
}

/* Markup an attacker could use to run script once parsed into the DOM. */
function injected(root) {
    return elements(root).flatMap(el => {
        const problems = [];
        if (['script', 'img', 'svg', 'iframe', 'object', 'embed', 'math', 'style', 'link', 'meta', 'base', 'form'].includes(el.localName)) problems.push(`<${el.localName}>`);
        for (const { name, value } of el.attributes) {
            if (name.startsWith('on')) problems.push(`${el.localName}[${name}]`);
            if (['autofocus', 'formaction', 'srcdoc'].includes(name)) problems.push(`${el.localName}[${name}]`);
            if (['href', 'src', 'action'].includes(name) && /^\s*javascript:/i.test(value)) problems.push(`${el.localName}[${name}=javascript:]`);
        }
        return problems;
    });
}

const settle = async (rounds = 3) => { for (let i = 0; i < rounds; i++) await new Promise(resolve => setImmediate(resolve)); };

/* Every value the given requests name: decoded path segments and the leaf
 * values of their JSON bodies. */
function idsNamed(calls) {
    const leaves = value => (value && typeof value === 'object' ? Object.values(value).flatMap(leaves) : [String(value)]);
    return new Set(calls.flatMap(call => [
        ...call.url.split('?')[0].split('/').map(decodeURIComponent),
        ...(typeof call.options.body === 'string' ? leaves(JSON.parse(call.options.body)) : [])]));
}

module.exports = { bootDashboard, response, injected, settle, idsNamed };
