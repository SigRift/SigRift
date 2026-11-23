const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

function panel() {
    const nodes = Object.fromEntries(['wifi-network-tbody', 'wifi-network-empty',
        'wifi-table-toggle', 'wifi-inv-context'].map(id => [id, {
        innerHTML: '', style: {}, querySelectorAll: () => [], closest: () => null,
    }]));
    const context = vm.createContext({
        document: {getElementById: id => nodes[id] || null, querySelectorAll: () => []},
        window: {}, esc: value => String(value ?? ''), fmtTime: () => '',
    });
    vm.runInContext(fs.readFileSync(path.join(__dirname,
        '../../../src/sigrift/bridge/static/wifi.js'), 'utf8'), context);
    return {ui: new context.WifiPanel({}), nodes};
}

for (const [security, label] of [[undefined, 'Unknown'], [null, 'Unknown'], ['', 'Unknown'],
    ['Unknown', 'Unknown'], ['Protected (unspecified)', 'Protected (unspecified)'],
    ['Open', 'Open'], ['WPA2/WPA', 'WPA2/WPA'], ['WPA3', 'WPA3']]) {
    test(`all actual Wi-Fi renderers preserve security certainty: ${String(security)}`, () => {
        const {ui, nodes} = panel();
        const row = {id: 1, bssid: '02:aa:bb:cc:dd:ee', ssid: 'network', security};
        ui._renderNetworkTable([row]);
        assert.ok(nodes['wifi-network-tbody'].innerHTML.includes(`<td>${label}</td>`));
        ui.netGroupKey = 'security';
        ui._renderNetworkTable([row]);
        assert.ok(nodes['wifi-network-tbody'].innerHTML.includes(`Security: ${label}`));
        assert.ok(ui._renderAnomalyCard(row).includes(`<span>${label}</span>`));
        ui._renderWifiInvContext(row);
        assert.ok(nodes['wifi-inv-context'].innerHTML.includes(
            `<span class="dd-field-label">Security</span><span class="dd-field-value">${label}</span>`));
    });
}

test('unknown and observed Open networks remain separate groups', () => {
    const {ui, nodes} = panel(); ui.netGroupKey = 'security';
    ui._renderNetworkTable([{bssid: '02:00:00:00:00:01', security: ''},
        {bssid: '02:00:00:00:00:02', security: 'Open'}]);
    assert.equal((nodes['wifi-network-tbody'].innerHTML.match(/class="wifi-net-group-header"/g) || []).length, 2);
    assert.ok(nodes['wifi-network-tbody'].innerHTML.includes('Security: Unknown'));
    assert.ok(nodes['wifi-network-tbody'].innerHTML.includes('Security: Open'));
});
