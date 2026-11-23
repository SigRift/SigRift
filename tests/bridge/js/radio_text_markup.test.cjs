/* Shipped Wi-Fi and Bluetooth tables render names heard over the air as text, never as markup.
 * The real esc() comes from dashboard.js, serialised the way the DOM serialises a text node. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const staticDir = path.resolve(__dirname, '../../../src/sigrift/bridge/static');

/* What esc() builds: a <div> holding one text node, serialised like the DOM does. */
class TextHolder {
    constructor() { this.text = ''; this.style = {}; }
    appendChild(node) { this.text += node.textContent; return node; }
    get innerHTML() { return this.text.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;'); }
    set innerHTML(value) { this.text = String(value); }
}

function load() {
    const ids = ['wifi-network-tbody', 'wifi-network-empty', 'wifi-table-toggle',
        'bt-device-tbody', 'bt-device-empty', 'bt-table-toggle'];
    const nodes = Object.fromEntries(ids.map(id => [id, {
        innerHTML: '', style: {}, querySelectorAll: () => [], closest: () => null,
    }]));
    const document = {
        hidden: false, addEventListener() {}, querySelectorAll: () => [],
        getElementById: id => nodes[id] || null,
        createElement: () => new TextHolder(), createTextNode: textContent => ({textContent}),
    };
    const context = {document, window: {}, console, setInterval() {}, clearInterval() {}};
    for (const name of ['dashboard.js', 'wifi.js', 'bluetooth.js']) {
        const filename = path.join(staticDir, name);
        vm.runInNewContext(fs.readFileSync(filename, 'utf8'), context, {filename});
    }
    return {context, nodes};
}

const markup = '<img src=x onerror=alert(1)>&amp;';
const escaped = '&lt;img src=x onerror=alert(1)&gt;&amp;amp;';

test('a Wi-Fi network row shows its SSID as text', () => {
    const {context, nodes} = load();
    const panel = new context.WifiPanel({});
    panel._renderNetworkTable([{bssid: '02:00:00:00:00:01', ssid: 'net ' + markup, security: 'WPA2'}]);
    const html = nodes['wifi-network-tbody'].innerHTML;
    assert.ok(html.includes('<td>net ' + escaped + '</td>'), html);
    assert.ok(!html.includes('<img'), html);
});

test('a Bluetooth device row shows its name and manufacturer as text', () => {
    const {context, nodes} = load();
    const panel = new context.BluetoothPanel({});
    panel._renderDeviceTable([{device_addr: '02:00:00:00:00:02', device_name: 'bt ' + markup,
        manufacturer: 'maker ' + markup, device_type: 'ble', rssi_dbm: -40}]);
    const html = nodes['bt-device-tbody'].innerHTML;
    assert.ok(html.includes('<td>bt ' + escaped + '</td>'), html);
    assert.ok(html.includes('<td>maker ' + escaped + '</td>'), html);
    assert.ok(!html.includes('<img'), html);
});
