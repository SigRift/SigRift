const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const root = path.resolve(__dirname, '../../..');
const staticRoot = path.join(root, 'src/sigrift/bridge/static');
function element(tag) {
    return {tag, textContent: '', disabled: false, hidden: false, attributes: {}, children: [], events: {}, focused:false,
        focus() {this.focused=true;},
        setAttribute(name, value) {this.attributes[name] = value;},
        appendChild(child) {this.children.push(child);}, replaceChildren() {this.children = [];},
        addEventListener(name, callback) {this.events[name] = callback;}};
}
function harness(collapsed = {}) {
    let now = 0, sequence = 0;
    const timers = new Map(), calls = [], replies = [];
    const elements = Object.fromEntries(['rows', 'status', 'refresh', 'toggle', 'body', 'overview'].map(id => ['setup-checklist-' + id, element(id)]));
    elements['scanner-warning-setup']=element('a');
    let saves=0;
    const context = {window: {}, console, Date, AbortController, performance: {now: () => now},
        document: {getElementById: id => elements[id], createElement: element},
        setTimeout(callback, delay) {timers.set(++sequence, {callback, at: now + delay}); return sequence;},
        clearTimeout: id => timers.delete(id)};
    for (const file of ['scanner_availability.js', 'setup_checklist.js']) {
        vm.runInNewContext(fs.readFileSync(path.join(staticRoot, file), 'utf8'), context, {filename: path.join(staticRoot, file)});
    }
    const ui = new context.window.SetupChecklist({collapsed, _saveCollapsed:()=>{saves++;}, apiFetch: (url, opts) => {
        calls.push(url); const reply = replies.shift();
        if (reply === 'hang') return new Promise((resolve,reject) => opts.signal.addEventListener('abort', () => reject(new Error('aborted'))));
        return reply instanceof Error ? Promise.reject(reply) : Promise.resolve(reply);
    }});
    return {ui, calls, replies, elements, saves:()=>saves, collapsed,
        text: () => elements['setup-checklist-rows'].children.map(row => row.children.map(cell => [cell.textContent,...cell.children.map(child=>child.textContent)].join(' ')).join(' | ')).join('\n'),
        message: () => elements['setup-checklist-status'].textContent,
        refresh: async data => {replies.push(data); await ui.refresh();},
        tick(ms) {const end = now + ms; for (;;) {
            const due = [...timers.entries()].filter(([, t]) => t.at <= end).sort((a,b) => a[1].at-b[1].at)[0];
            if (!due) break; now=due[1].at; timers.delete(due[0]); due[1].callback();
        } now=end;}};
}
function snapshot(state = null, observations = {}) {
    return {host_inventory: 'unreported', generated_at: '2026-11-07T15:00:00Z', truncated: false,
        nodes: [{node_id: 'lab-node', scanner_status: state ? {wifi: {protocol: 'wifi', state, active: state === 'running',
            reported_at: '2026-11-07T15:00:00Z', expires_in_seconds: state === 'running' ? 120 : 0}} : {},
            observations: {rf_record: {status: 'empty', timestamp: null}, rf_summary: {status: 'empty', timestamp: null},
                wifi_record: {status: 'empty', timestamp: null}, ...observations}}]};
}
test('empty setup and generic online inventory do not invent absent adapters or running capture', async () => {
    const h=harness(), empty=snapshot(); empty.nodes=[]; await h.refresh(empty);
    assert.match(h.text(), /No nodes registered/); assert.match(h.text(), /unreported, not “no adapter”/);
    const data=snapshot(); data.nodes[0].status='active'; data.nodes[0].capabilities={hardware:'RTL-SDR', private_serial:'secret'};
    await h.refresh(data); assert.match(h.text(), /Unreported — host check needed/); assert.match(h.text(), /Not reported/);
    assert.doesNotMatch(h.text(), /Running|secret|Offline/);
});
test('quiet healthy capture has no data yet and does not become offline', async () => {
    const h=harness(); await h.refresh(snapshot('running'));
    assert.match(h.text(), /Running — capture verified/); assert.match(h.text(), /No stored observations/);
    assert.match(h.text(), /Quiet air/); assert.doesNotMatch(h.text(), /Offline/);
});
test('failed refresh retains last observations but actual lease expires without another response', async () => {
    const h=harness(); await h.refresh(snapshot('running')); h.tick(90000);
    await h.refresh(new Error('secret network error')); assert.match(h.message(), /Refresh failed/);
    assert.doesNotMatch(h.message(), /secret/); assert.match(h.text(), /Running/);
    h.tick(30000); assert.doesNotMatch(h.text(), /Running/); assert.match(h.text(), /Report expired/);
    await h.refresh(snapshot('running')); assert.doesNotMatch(h.text(), /Running/); // replay cannot renew
    const fresh=snapshot('running'); fresh.nodes[0].scanner_status.wifi.reported_at='2026-11-07T15:02:00Z';
    await h.refresh(fresh); assert.match(h.text(), /Running/); assert.doesNotMatch(h.message(), /failed/);
});
for (const state of ['error','stopped']) test(`${state} yields a targeted remedy without discarding observations`, async () => {
    const h=harness(); await h.refresh(snapshot(state,{wifi_record:{status:'available',timestamp:'2026-11-07T14:00:00Z'}}));
    assert.match(h.text(), new RegExp(state==='error'?'Capture error':'Stopped'));
    assert.match(h.text(), /2026-11-07T14:00:00.000Z/); assert.doesNotMatch(h.text(), /Running/);
    assert.match(h.text(), state==='error'? /wifi-scan logs/:/saved selection/);
});
test('partial database failure preserves capture and independently reports missing data check', async () => {
    const h=harness(); await h.refresh(snapshot('running',{wifi_record:{status:'unavailable',timestamp:null}}));
    assert.match(h.text(), /Running/); assert.match(h.text(), /Data check unavailable — retry/);
    await h.refresh(snapshot('running')); assert.match(h.text(), /No stored observations/);
    assert.doesNotMatch(h.text(), /Data check unavailable/);
});
test('summary hour is labeled separately and newest actual timestamp wins', async () => {
    const h=harness(); await h.refresh(snapshot(null,{
        rf_record:{status:'available',timestamp:'2026-11-07T09:00:00-06:00'},
        rf_summary:{status:'available',timestamp:'2026-11-07T16:00:00Z'}}));
    assert.match(h.text(), /2026-11-07T16:00:00.000Z \(summary hour\)/);
    assert.doesNotMatch(h.text(), /Running/);
    await h.refresh(snapshot(null,{rf_record:{status:'available',timestamp:'2026-11-07T17:00:00Z'},rf_summary:{status:'invalid',timestamp:null}}));
    assert.match(h.text(), /17:00:00.000Z \(record time\) · other data unavailable/);
});
for (const invalid of [null, {}, {host_inventory:'ready'}, {host_inventory:'unreported',nodes:[],truncated:false,generated_at:'bad'}]) {
    test(`invalid snapshot fails without manufacturing success: ${JSON.stringify(invalid)}`, async()=>{
        const h=harness();await h.refresh(invalid); assert.match(h.message(),/unavailable/); assert.equal(h.text(),'');
        assert.equal(h.elements['setup-checklist-refresh'].disabled,false);
    });
}
test('click refresh uses only one read in flight and recovers after failure', async()=>{
    const h=harness();let finish;h.replies.push(new Promise(resolve=>{finish=resolve;}));
    const first=h.ui.refresh();h.elements['setup-checklist-refresh'].events.click();
    assert.equal(h.calls.length,1);assert.equal(h.elements['setup-checklist-refresh'].disabled,true);
    finish(snapshot());await first; assert.equal(h.elements['setup-checklist-refresh'].disabled,false);
    await h.refresh(new Error('failure'));await h.refresh(snapshot());
    assert.ok(h.calls.every(url=>url==='/api/nodes/setup-checklist'));assert.doesNotMatch(h.message(),/failed/);
});
test('untrusted node names remain text and capped inventory is explicit', async()=>{
    const h=harness(),data=snapshot();data.truncated=true;data.nodes[0].node_id='<img onerror=secret()>';
    await h.refresh(data);assert.match(h.text(),/<img onerror=secret\(\)>/);assert.match(h.message(),/first 100/);
    assert.ok(h.elements['setup-checklist-rows'].children.every(row=>row.children[0].children.length===0));
});
test('shipped checklist is on Summary with external CSP-compatible code and valid read-only helper action',()=>{
    const html=fs.readFileSync(path.join(root,'src/sigrift/bridge/templates/index.html'),'utf8');
    const panel=html.slice(html.indexOf('<section class="card" id="panel-setup-checklist">'),html.indexOf('<!-- Summary Overview Stats'));
    assert.match(panel,/data-help-label="Setup and capture checklist"/);
    assert.match(panel,/scanner_setup.py plan --scanners=auto/);assert.doesNotMatch(panel,/scanner_setup.py discover/);
    assert.match(html,/path='setup_checklist.js'/);assert.match(html,/path='setup_checklist.css'/);
    assert.match(panel,/wlan0/);assert.match(panel,/No hardware or privilege-changing command runs from this page/);
});

test('a hung request aborts at its deadline, keeps expiry and permits a manual retry', async()=>{
    const h=harness();await h.refresh(snapshot('running'));h.replies.push('hang');const request=h.ui.refresh();
    h.tick(10000);await request;assert.match(h.message(),/Refresh failed/);assert.equal(h.elements['setup-checklist-refresh'].disabled,false);
    await h.refresh(snapshot('running'));assert.doesNotMatch(h.message(),/failed/);assert.match(h.text(),/Running/);
});
for (const item of [{status:'available',timestamp:null},{status:'available',timestamp:'bad'},{status:'empty',timestamp:'2026-01-01Z'},{status:'unknown',timestamp:null}]) test('malformed observation cannot be displayed as empty: '+JSON.stringify(item),async()=>{
    const h=harness();await h.refresh(snapshot(null,{wifi_record:item}));assert.match(h.message(),/unavailable/);assert.equal(h.text(),'');
});

function withReceipt(data=snapshot(), change={}) {
    data.host_inventory='per_node';
    data.nodes[0].setup_readiness={checked_at:'2026-11-07T15:00:00Z',fresh:true,expires_in_seconds:300,
        sdr:{adapter:'ready',selection:'selected',reason:'checked'},
        wifi:{adapter:'missing',selection:'not_selected',reason:'not_found'},...change};
    return data;
}
test('host receipt: ready, absent and capture/data stay independent',async()=>{
    const h=harness();await h.refresh(withReceipt());
    assert.match(h.text(),/Ready when checked · saved choice/);assert.match(h.text(),/No supported adapter found · not selected/);
    assert.match(h.text(),/Not reported/);assert.match(h.text(),/No stored observations/);assert.doesNotMatch(h.text(),/Running/);
    assert.match(h.message(),/not continuous inventory/);
});
test('host receipt: freshness expires on failed refresh without asking for five-minute reruns',async()=>{
    const h=harness();await h.refresh(withReceipt());h.tick(299000);
    await h.refresh(new Error('secret'));assert.match(h.text(),/recent host check/);
    h.tick(1000);assert.match(h.text(),/stale host check/);assert.doesNotMatch(h.text(),/recent host check/);
    assert.doesNotMatch(h.text(),/every five|every 5|offline/i);
    await h.refresh(withReceipt());assert.doesNotMatch(h.text(),/recent host check/);
    const older=withReceipt();older.nodes[0].setup_readiness.checked_at='2026-11-07T14:59:59Z';
    await h.refresh(older);await h.refresh(withReceipt());assert.doesNotMatch(h.text(),/recent host check/);
    await h.refresh(withReceipt(snapshot(),{checked_at:'2026-11-07T15:06:00Z'}));assert.match(h.text(),/recent host check/);
});
test('host receipt: stale check never overrides a new quiet capture lease',async()=>{
    const h=harness();await h.refresh(withReceipt(snapshot('running'),{fresh:false,expires_in_seconds:0}));
    assert.match(h.text(),/stale host check/);assert.match(h.text(),/Running — capture verified/);assert.match(h.text(),/Quiet air/);
});
for(const [reason,adapter,expected] of [['selected_absent','missing',/Reconnect the saved adapter/],['permissions','blocked',/selected device permissions/],['management_interface','blocked',/never disconnect wlan0/]]) {
    test('host receipt: targeted safe remedy for '+reason,async()=>{
        const h=harness();await h.refresh(withReceipt(snapshot(),{wifi:{adapter,selection:'selected',reason}}));
        assert.match(h.text(),expected);assert.doesNotMatch(h.text(),/Running/);
    });
}
test('host receipt: dashboard-only and failed host discovery are unknown, never absent',async()=>{
    const h=harness();await h.refresh(withReceipt(snapshot(),{
        sdr:{adapter:'unknown',selection:'not_selected',reason:'not_checked'},
        wifi:{adapter:'unknown',selection:'selected',reason:'probe_failed'}}));
    assert.match(h.text(),/Not checked \(dashboard-only\)/);assert.match(h.text(),/Host check incomplete/);
    assert.doesNotMatch(h.text(),/No supported adapter found/);
});
for(const change of [{fresh:true,expires_in_seconds:999},{fresh:true,expires_in_seconds:0},{checked_at:'secret'},
    {sdr:{adapter:'blocked',reason:'SSID-secret',selection:'selected'}}]) {
    test('host receipt: malformed evidence fails closed '+JSON.stringify(change),async()=>{
        const h=harness();await h.refresh(withReceipt(snapshot(),change));assert.match(h.message(),/unavailable/);assert.equal(h.text(),'');
    });
}


test('checklist collapse is explicit, remembered, and warning recovery restores keyboard focus', async()=>{
    const h=harness({'setup-checklist':true,other:true});
    assert.equal(h.elements['setup-checklist-body'].hidden,true);
    assert.equal(h.elements['setup-checklist-toggle'].attributes['aria-expanded'],'false');
    h.elements['setup-checklist-toggle'].events.click();
    assert.equal(h.elements['setup-checklist-body'].hidden,false);
    assert.equal(h.elements['setup-checklist-toggle'].attributes['aria-expanded'],'true');
    assert.equal(h.collapsed['setup-checklist'],false);assert.equal(h.collapsed.other,true);assert.equal(h.saves(),1);
    h.elements['setup-checklist-toggle'].events.click();
    let prevented=false;h.elements['scanner-warning-setup'].events.click({preventDefault(){prevented=true;}});assert.equal(prevented,true);
    assert.equal(h.elements['setup-checklist-body'].hidden,false);
    assert.equal(h.elements['setup-checklist-toggle'].focused,true);
    assert.equal(h.collapsed['setup-checklist'],false);
});
test('collapsed header retains current capture failure and expires lease without reopening',async()=>{
    const h=harness({'setup-checklist':true});await h.refresh(snapshot('running'));
    assert.match(h.elements['setup-checklist-overview'].textContent,/1 capture running/);
    h.tick(120000);
    assert.match(h.elements['setup-checklist-overview'].textContent,/1 scanner needs attention/);
    assert.equal(h.elements['setup-checklist-body'].hidden,true);
    await h.refresh(new Error('private failure'));
    assert.match(h.elements['setup-checklist-overview'].textContent,/refresh failed/);
    assert.doesNotMatch(h.elements['setup-checklist-overview'].textContent,/private/);
});
test('individual adapter, capture and stored-data statuses retain independent evidence',async()=>{
    const h=harness();await h.refresh(withReceipt(snapshot('running'),{wifi:{adapter:'ready',selection:'selected',reason:'checked'}}));
    let wifi=h.elements['setup-checklist-rows'].children[1];
    assert.equal(wifi.children[1].attributes['data-check-state'],'ready');
    assert.equal(wifi.children[2].attributes['data-check-state'],'running');
    assert.equal(wifi.children[3].attributes['data-check-state'],'empty');
    h.tick(300000);wifi=h.elements['setup-checklist-rows'].children[1];
    assert.equal(wifi.children[1].attributes['data-check-state'],'stale');
    assert.equal(wifi.children[2].attributes['data-check-state'],'expired');
    assert.equal(wifi.children[3].attributes['data-check-state'],'empty');
});
test('failed data lookup is actionable even with healthy capture, not all checks complete',async()=>{
    const h=harness();await h.refresh(snapshot('running',{wifi_record:{status:'unavailable',timestamp:null}}));
    const wifi=h.elements['setup-checklist-rows'].children[1];
    assert.equal(wifi.children[2].attributes['data-check-state'],'running');
    assert.equal(wifi.children[3].attributes['data-check-state'],'unavailable');
    assert.match(wifi.children[4].textContent,/Retry status/);
    assert.match(h.elements['setup-checklist-overview'].textContent,/1 scanner needs attention/);
});
test('unselected missing adapter and quiet capture do not become false setup failures',async()=>{
    const h=harness();await h.refresh(withReceipt(snapshot('running')));
    assert.doesNotMatch(h.elements['setup-checklist-overview'].textContent,/needs attention/);
    const wifi=h.elements['setup-checklist-rows'].children[1];
    assert.equal(wifi.children[1].attributes['data-check-state'],'not_selected');
    assert.equal(wifi.children[2].attributes['data-check-state'],'running');
    assert.equal(wifi.children[3].attributes['data-check-state'],'empty');
});

test('header attention reflects initial failure and clears on an empty successful inventory',async()=>{
    const h=harness();h.ui.render();
    assert.equal(h.elements['setup-checklist-overview'].attributes['data-needs-attention'],'false');
    await h.refresh(new Error('private initial failure'));
    assert.equal(h.elements['setup-checklist-overview'].attributes['data-needs-attention'],'true');
    assert.match(h.elements['setup-checklist-overview'].textContent,/unavailable/);
    const empty=snapshot();empty.nodes=[];
    await h.refresh(empty);
    assert.equal(h.elements['setup-checklist-overview'].attributes['data-needs-attention'],'false');
    assert.equal(h.elements['setup-checklist-overview'].textContent,'No registered nodes');
    await h.refresh(snapshot('error'));
    assert.equal(h.elements['setup-checklist-overview'].attributes['data-needs-attention'],'true');
    await h.refresh(empty);
    assert.equal(h.elements['setup-checklist-overview'].attributes['data-needs-attention'],'false');
});

// Status reasons sent with an "error" report (sensor lifecycle contract).
function failingSnapshot(protocol, reason, reportedAt = '2026-11-07T15:00:00Z') {
    const data = snapshot();
    data.nodes[0].scanner_status = {[protocol]: {protocol, state: 'error', active: false, reported_at: reportedAt, expires_in_seconds: 0, reason}};
    return data;
}
function protocolRow(h, protocol) { return h.elements['setup-checklist-rows'].children[protocol === 'sdr' ? 0 : 1]; }
// Same advice as the dashboard warning (scanner_availability.test.cjs).
const absentAdvice = {
    sdr: 'The SDR sensor is not connected. Reconnect it to the same USB port and capture resumes by itself. If it is on another port, run setup again on this node.',
    wifi: 'The Wi-Fi sensor is not connected. Reconnect it to the same USB port and capture resumes by itself. If it is on another port or came back under another interface name, run setup again on this node.',
};
const unusableAdvice = {
    sdr: 'The SDR sensor is connected, but the scanner cannot open it. Prepare it on this node again with scanner_setup.py prepare-rtl. QUICKSTART explains how to make that last across re-plugs.',
    wifi: 'The Wi-Fi sensor is connected, but the scanner cannot open it. Prepare it on this node again.',
};
for (const [protocol, label] of [['sdr', 'SDR'], ['wifi', 'Wi-Fi']]) {
    for (const [reason, state, detail, remedy, attention] of [
        ['sensor_absent', 'sensor_absent', 'Sensor not connected', absentAdvice[protocol], true],
        ['sensor_changed', 'sensor_changed', 'Different sensor connected', `A different ${label} sensor is connected where the selected one was. Run setup again on this node to use it.`, true],
        ['sensor_unusable', 'sensor_unusable', 'Sensor cannot be opened', unusableAdvice[protocol], true],
        ['starting', 'starting', 'Starting capture', 'The scanner has started and is not capturing yet. No action is needed.', false],
        ['capture_failed', 'error', 'Capture error', 'Inspect ', true],
        [null, 'error', 'Capture error', 'Inspect ', true],
        ['usb_gremlins', 'error', 'Capture error', 'Inspect ', true],
    ]) test(`${protocol} capture reason ${reason} is shown as ${state}`, async () => {
        const h = harness(); await h.refresh(failingSnapshot(protocol, reason));
        const cells = protocolRow(h, protocol).children;
        assert.equal(cells[2].attributes['data-check-state'], state);
        assert.equal(cells[2].children[1].textContent, detail);
        assert.ok(cells[4].textContent.startsWith(remedy), cells[4].textContent);
        if (remedy.endsWith('.')) assert.equal(cells[4].textContent, remedy);
        assert.doesNotMatch(h.text(), /usb_gremlins/);
        assert.equal(/needs attention/.test(h.elements['setup-checklist-overview'].textContent), attention);
    });
}
test('a reconnected sensor shows as running on the next checklist refresh', async () => {
    const h = harness(); await h.refresh(failingSnapshot('wifi', 'sensor_absent'));
    assert.equal(protocolRow(h, 'wifi').children[2].attributes['data-check-state'], 'sensor_absent');
    const recovered = snapshot('running'); recovered.nodes[0].scanner_status.wifi.reported_at = '2026-11-07T15:00:30Z';
    h.tick(20000); await h.refresh(recovered);
    assert.equal(protocolRow(h, 'wifi').children[2].attributes['data-check-state'], 'running');
    assert.doesNotMatch(h.elements['setup-checklist-overview'].textContent, /needs attention/);
});
