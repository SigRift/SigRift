const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const file = path.resolve(__dirname, '../../../src/sigrift/bridge/static/known_signals.js');
const source = fs.readFileSync(file, 'utf8');
const dashboardSource = fs.readFileSync(path.resolve(__dirname, '../../../src/sigrift/bridge/static/dashboard.js'), 'utf8');
const bandDefinition = dashboardSource.match(/BridgeDashboard\.prototype\._CB_FREQ_BANDS = (\[[\s\S]*?\]);/);
assert.ok(bandDefinition, 'Actual dashboard band source must be present');
const dashboardBands = JSON.parse(JSON.stringify(vm.runInNewContext(bandDefinition[1])));
const settle = () => new Promise(resolve => setImmediate(resolve));
class Element {
    constructor(tag) { this.tagName = tag; this.children = []; this.events = {}; this.attrs = {}; this.textContent = ''; this.value = ''; this.disabled = false; }
    appendChild(child) { this.children.push(child); child.parent = this; return child; }
    replaceChildren(...children) { this.children = []; children.forEach(c => this.appendChild(c)); }
    addEventListener(name, fn) { (this.events[name] ||= []).push(fn); }
    setAttribute(name, value) { this.attrs[name] = value; }
    getAttribute(name) { return this.attrs[name]; }
    querySelectorAll(selector) { return this.children.flatMap(c => [...((selector === 'input' && c.tagName === 'input') || (selector === '[data-known-detection]' && c.attrs['data-known-detection']) ? [c] : []), ...c.querySelectorAll(selector)]); }
    remove() { if (this.parent) this.parent.children = this.parent.children.filter(c => c !== this); }
    showModal() { this.open = true; }
    close() { this.open = false; this.fire('close'); }
    fire(name) { for (const fn of this.events[name] || []) fn({ preventDefault() {} }); }
    click() { if (!this.disabled) this.fire('click'); }
}
function walk(node) { return [node, ...node.children.flatMap(walk)]; }
const defaults = {freq_min_hz:399950000, freq_max_hz:400050000, signal_class:'bpsk',node_id:'rf-one',note:''};
const saved = {...defaults,pattern_id:'rule-one',revision:1};
function fixture(responses, nodeResponse = [], bands = dashboardBands) {
    const body = new Element('body'), requests = [], events = {};
    const context = {window:{confirm:()=>true},document:{body,createElement:tag=>new Element(tag),getElementById:()=>null,addEventListener:(name,fn)=>{events[name]=fn;}}};
    vm.runInNewContext(source,context,{filename:file});
    const db={_CB_FREQ_BANDS:bands,apiFetch:async (url,options)=>{requests.push({url,options});if(url==='/api/nodes/'){if(nodeResponse instanceof Error)throw nodeResponse;return nodeResponse;}assert.ok(responses.length,'Unexpected request'); const value=responses.shift();if(value instanceof Error)throw value;return await value;}};
    return {body,requests,db,api:context.window.KnownSignals,events,
        field(name){return walk(body).find(n=>n.name===name);},
        button(text){return walk(body).find(n=>n.tagName==='button'&&n.textContent===text);},
        status(){return walk(body).find(n=>n.attrs.role==='status').textContent;},
        submit(){walk(body).find(n=>n.tagName==='form').fire('submit');},
        async open(can_manage=true){responses.unshift({detection_id:'source',defaults,can_manage,matching_patterns:[]});this.api.open(db,'source');await settle();},
    };
}
test('actual controller reviews exact default node/class/range before any mutation',async()=>{
    const f=fixture([]);await f.open();assert.equal(f.requests.length,1);assert.equal(f.requests[0].options,undefined);
    assert.equal(f.field('freq_min_mhz').value,'399.95');assert.equal(f.field('freq_max_mhz').value,'400.05');assert.equal(f.field('node_id').value,'rf-one');assert.equal(f.field('all_nodes').checked,false);assert.equal(f.field('signal_class').readOnly,true);
});
test('successful save preserves intended scope and offers revision-bound undo',async()=>{
    const f=fixture([{baselined:true,pattern:saved},{removed:true}]);await f.open();f.submit();await settle();
    assert.deepEqual(JSON.parse(JSON.stringify(f.requests[1].options.body)),{...defaults,signal_class:'*'});assert.match(f.status(),/saved/);
    f.button('Undo / remove this pattern').click();await settle();assert.equal(f.requests[2].url,'/api/detections/known-signals/rule-one?revision=1');assert.match(f.status(),/enabled again/);
});
test('global scope requires the explicit checkbox',async()=>{
    const f=fixture([{baselined:true,pattern:{...saved,node_id:null}}]);await f.open();f.field('all_nodes').checked=true;f.field('all_nodes').fire('change');f.submit();await settle();assert.equal(f.requests[1].options.body.node_id,null);
});
test('failed save retains the reviewed fields and a genuine retry',async()=>{
    const f=fixture([new Error('Database unavailable'),{baselined:true,pattern:saved}]);await f.open();f.field('note').value='reviewed reason';f.submit();await settle();assert.match(f.status(),/Database unavailable/);assert.equal(f.field('note').value,'reviewed reason');assert.equal(f.button('Save known pattern').disabled,false);f.submit();await settle();assert.equal(f.requests.length,3);assert.match(f.status(),/saved/);
});
test('pending click and Enter cannot submit two mutations',async()=>{
    let complete;const f=fixture([new Promise(resolve=>{complete=resolve;})]);await f.open();f.submit();f.submit();assert.equal(f.requests.length,2);assert.equal(f.button('Save known pattern').disabled,true);complete({baselined:true,pattern:saved});await settle();assert.match(f.status(),/saved/);
});
for(const value of ['', 'Infinity','-1','500'])test(`invalid minimum ${JSON.stringify(value)} prevents save`,async()=>{
    const f=fixture([]);await f.open();f.field('freq_min_mhz').value=value;f.submit();await settle();assert.equal(f.requests.length,1);assert.match(f.status(),/valid increasing/);
});
test('viewer cannot mutate through buttons or a submitted form',async()=>{
    const f=fixture([]);await f.open(false);assert.equal(f.button('Save known pattern').disabled,true);assert.equal(f.field('all_nodes').disabled,true);f.submit();await settle();assert.equal(f.requests.length,1);assert.match(f.status(),/Read-only/);
});
test('unconfirmed response is not announced as a saved pattern',async()=>{
    const f=fixture([{baselined:true}]);await f.open();f.submit();await settle();assert.match(f.status(),/not confirmed/);assert.equal(f.button('Undo / remove this pattern'),undefined);
});
test('manager edits exact pattern revision and preserves literal markup as text',async()=>{
    const dangerous='<img src=x onerror=alert(1)> &quot;';const pattern={...saved,note:dangerous};
    const f=fixture([{patterns:[pattern],can_manage:true},{...pattern,revision:2}]);f.api.list(f.db);await settle();assert.ok(walk(f.body).some(n=>n.textContent===dangerous));assert.equal(walk(f.body).some(n=>n.tagName==='img'),false);
    f.button('Edit').click();assert.match(f.status(),/saved scope/);assert.doesNotMatch(f.status(),/50 kHz/);assert.equal(f.field('note').value,dangerous);f.field('freq_max_mhz').value='400.1';f.submit();await settle();assert.equal(f.requests[1].options.body.revision,1);assert.equal(f.requests[1].options.body.freq_max_hz,400100000);
});
test('remove conflict keeps the entry and exposes its error',async()=>{
    const f=fixture([{patterns:[saved],can_manage:true},new Error('Refresh changed pattern')]);f.api.list(f.db);await settle();f.button('Remove').click();await settle();assert.match(f.status(),/Refresh changed pattern/);assert.ok(f.button('Edit'));assert.equal(f.button('Remove').disabled,false);
});
test('viewer manager offers neither edit nor remove',async()=>{
    const f=fixture([{patterns:[saved],can_manage:false}]);f.api.list(f.db);await settle();assert.equal(f.button('Edit'),undefined);assert.equal(f.button('Remove'),undefined);assert.match(f.status(),/Read-only/);
});
test('eligible detection binding uses encoded server ID without mutation',async()=>{
    const f=fixture([new Error('Not found')]);const c=new Element('div'),b=new Element('button');b.attrs['data-known-detection']='id/with?symbols';c.appendChild(b);f.api.bind(c,f.db);b.click();await settle();assert.equal(f.requests[0].url,'/api/detections/anomalies/id%2Fwith%3Fsymbols/baseline');assert.equal(f.requests[0].options,undefined);assert.match(f.status(),/Not found/);
});

test('new reviewed form explicitly defaults to any modulation with visible source class',async()=>{
    const f=fixture([{baselined:true,pattern:{...saved,signal_class:'*'}}]);await f.open();
    assert.equal(f.field('any_modulation').checked,true);
    assert.equal(f.field('signal_class').value,'bpsk');assert.equal(f.field('signal_class').disabled,true);
    f.submit();await settle();assert.equal(f.requests[1].options.body.signal_class,'*');
    assert.ok(walk(f.body).some(n=>n.textContent.includes('Any modulation (frequency only)')));
    assert.equal(walk(f.body).some(n=>n.textContent.includes(' · * · ')),false);
});
test('new reviewed form can opt back into actual source class',async()=>{
    const f=fixture([{baselined:true,pattern:saved}]);await f.open();
    f.field('any_modulation').checked=false;f.field('any_modulation').fire('change');
    assert.equal(f.field('signal_class').disabled,false);assert.equal(f.field('signal_class').required,true);
    f.submit();await settle();assert.equal(f.requests[1].options.body.signal_class,'bpsk');
});
for (const signal_class of ['bpsk','*']) test(`editing preserves saved mode ${signal_class}`,async()=>{
    const pattern={...saved,signal_class};const f=fixture([{patterns:[pattern],can_manage:true},{...pattern,revision:2}]);
    f.api.list(f.db);await settle();f.button('Edit').click();
    assert.equal(f.field('any_modulation').checked,signal_class==='*');
    f.submit();await settle();assert.equal(f.requests[1].options.body.signal_class,signal_class);
});
for(const value of ['', '*', 'b*','qpsk ', '<b>', 'qpsk\n', 'a'.repeat(129)])test(`specific mode rejects ${JSON.stringify(value)} without a mutation`,async()=>{
    const pattern={...saved,signal_class:'*'};const f=fixture([{patterns:[pattern],can_manage:true}]);f.api.list(f.db);await settle();f.button('Edit').click();
    f.field('any_modulation').checked=false;f.field('any_modulation').fire('change');f.field('signal_class').value=value;
    f.submit();await settle();assert.equal(f.requests.length,1);assert.match(f.status(),/valid signal class/);
});
test('editing any modulation can narrow to a validated specific class',async()=>{
    const pattern={...saved,signal_class:'*'};const f=fixture([{patterns:[pattern],can_manage:true},{...saved,signal_class:'qpsk',revision:2}]);f.api.list(f.db);await settle();f.button('Edit').click();
    f.field('any_modulation').checked=false;f.field('any_modulation').fire('change');f.field('signal_class').value='qpsk';f.submit();await settle();
    assert.equal(f.requests[1].options.body.signal_class,'qpsk');assert.equal(f.requests[1].options.body.revision,1);
});
test('read-only form cannot enable frequency-only or specific controls',async()=>{
    const f=fixture([]);await f.open(false);assert.equal(f.field('any_modulation').disabled,true);
    f.field('any_modulation').checked=false;f.field('any_modulation').fire('change');
    assert.equal(f.field('signal_class').disabled,true);f.submit();await settle();assert.equal(f.requests.length,1);
});

test('settings is available with no detections and FM preset only opens an editable review',async()=>{
    const f=fixture([{patterns:[],can_manage:true}]);f.api.settings(f.db);await settle();
    f.button('Ignore FM broadcast range…').click();
    assert.equal(f.field('freq_min_mhz').value,'88');assert.equal(f.field('freq_max_mhz').value,'108');
    assert.equal(f.field('any_modulation').checked,true);assert.equal(f.field('node_id').value,'');assert.equal(f.field('all_nodes').checked,false);
    assert.equal(f.requests.length,2);assert.match(f.status(),/region/);
    f.submit();assert.equal(f.requests.length,2);assert.match(f.status(),/node/);
});
test('reviewed FM creation posts exact editable range and explicit node without fabricated detection',async()=>{
    const band={...saved,freq_min_hz:87500000,freq_max_hz:108e6,signal_class:'*',node_id:'receiver-one',source_detection_id:null};
    const f=fixture([{patterns:[],can_manage:true},band,{removed:true}]);f.api.settings(f.db);await settle();f.button('Ignore FM broadcast range…').click();
    f.field('freq_min_mhz').value='87.5';f.field('node_id').value='receiver-one';f.submit();await settle();
    assert.equal(f.requests[2].url,'/api/detections/known-signals');assert.equal(f.requests[2].options.method,'POST');
    const body=f.requests[2].options.body;assert.equal(body.freq_min_hz,87500000);assert.equal(body.freq_max_hz,108e6);assert.equal(body.node_id,'receiver-one');assert.equal(body.signal_class,'*');assert.equal('revision' in body,false);assert.equal('source_detection_id' in body,false);
    assert.match(f.status(),/saved/);f.button('Remove this pattern').click();await settle();assert.match(f.requests[3].url,/revision=1$/);
});
test('custom frequency rule requires valid input and explicit all-node review',async()=>{
    const f=fixture([{patterns:[],can_manage:true},{...saved,node_id:null}]);f.api.settings(f.db);await settle();f.button('Add custom frequency range').click();
    assert.equal(f.field('freq_min_mhz').value,'');assert.equal(f.field('freq_max_mhz').value,'');f.submit();assert.equal(f.requests.length,2);
    f.field('freq_min_mhz').value='900';f.field('freq_max_mhz').value='910';f.field('all_nodes').checked=true;f.field('all_nodes').fire('change');f.submit();await settle();assert.equal(f.requests[2].options.body.node_id,null);
});
test('failed direct create retains reviewed values and prevents duplicate pending submission',async()=>{
    let resolve;const f=fixture([{patterns:[],can_manage:true},new Promise(r=>{resolve=r;}),{...saved,source_detection_id:null}]);f.api.settings(f.db);await settle();f.button('Ignore FM broadcast range…').click();f.field('node_id').value='rf';f.submit();f.submit();assert.equal(f.requests.length,3);
    resolve({});await settle();assert.match(f.status(),/not confirmed/);assert.equal(f.field('node_id').value,'rf');assert.equal(f.button('Save alert rule').disabled,false);f.submit();await settle();assert.equal(f.requests.length,4);
});
test('viewer settings has no create/edit/remove control',async()=>{
    const f=fixture([{patterns:[saved],can_manage:false}]);f.api.settings(f.db);await settle();
    for(const label of ['Ignore FM broadcast range…','Add custom frequency range','Edit','Remove'])assert.equal(f.button(label),undefined);
    assert.match(f.status(),/Read-only/);
});
test('settings guidance distinguishes manual suppression from automatic frequency novelty',async()=>{
    const f=fixture([{patterns:[],can_manage:true}]);f.api.settings(f.db);await settle();const copy=walk(f.body).map(n=>n.textContent).join(' ');
    assert.match(copy,/does not automatically alert only on new frequencies/);assert.match(copy,/Detections, scores and existing alerts stay available/);
});

test('duplicate direct creation displays returned existing note and exact revision for removal',async()=>{
    const existing={...saved,signal_class:'*',note:'Original reviewed reason',revision:5};
    const f=fixture([{patterns:[],can_manage:true},existing,{removed:true}]);f.api.settings(f.db);await settle();f.button('Ignore FM broadcast range…').click();f.field('node_id').value='rf-one';f.field('note').value='A proposed different reason';f.submit();await settle();
    assert.ok(walk(f.body).some(n=>n.textContent==='Original reviewed reason'));assert.equal(walk(f.body).some(n=>n.textContent==='A proposed different reason'),false);
    assert.equal(f.button('Undo / remove this pattern'),undefined);f.button('Remove this pattern').click();await settle();assert.match(f.requests[3].url,/revision=5$/);
});
test('direct create exposes registered node suggestions without selecting or broadening scope',async()=>{
    const f=fixture([{patterns:[],can_manage:true}],[{node_id:'rf-one'},{node_id:'<receiver>'},{node_id:'rf-one'},{}]);f.api.settings(f.db);await settle();f.button('Ignore FM broadcast range…').click();await settle();
    assert.equal(f.field('node_id').getAttribute('list'),'known-signal-node-options');assert.deepEqual(walk(f.body).filter(n=>n.tagName==='option').map(n=>n.value),['rf-one','<receiver>']);assert.equal(walk(f.body).some(n=>n.tagName==='receiver'),false);
    assert.equal(f.field('node_id').value,'');assert.equal(f.field('all_nodes').checked,false);assert.ok(walk(f.body).some(n=>n.textContent.includes('Registration alone does not confirm capture')));
});
test('failed node suggestions preserve manual entry and never select all nodes',async()=>{
    const f=fixture([{patterns:[],can_manage:true},{...saved,source_detection_id:null}],new Error('Private node-list failure'));f.api.settings(f.db);await settle();f.button('Ignore FM broadcast range…').click();await settle();
    assert.ok(walk(f.body).some(n=>n.textContent.includes('Node suggestions unavailable')));assert.equal(f.field('all_nodes').checked,false);f.field('node_id').value='known-rf';f.submit();await settle();assert.equal(f.requests[2].options.body.node_id,'known-rf');
});

const expectedBands = [
    ['FM Broadcast', 88, 108], ['VHF Air', 108, 137], ['ISM 433', 433.05, 434.79],
    ['ISM 868', 863, 870], ['ISM 915', 902, 928], ['GSM 900', 880, 960],
    ['WiFi 2.4G', 2400, 2500], ['WiFi 5G', 5150, 5850]
];
for (const [label, minimum, maximum] of expectedBands) test(`named band ${label} uses actual dashboard source and opens editable MHz review only`, async()=>{
    const f=fixture([{patterns:[],can_manage:true}]);f.api.settings(f.db);await settle();
    const picker=f.field('named_rf_band');assert.ok(picker);
    const option=picker.children.find(n=>n.textContent.startsWith(label+' · '));assert.ok(option);
    picker.value=option.value;picker.fire('change');assert.equal(f.requests.length,1);
    f.button('Review selected band').click();await settle();
    assert.equal(f.field('freq_min_mhz').value,String(minimum));assert.equal(f.field('freq_max_mhz').value,String(maximum));
    assert.equal(f.field('freq_min_mhz').readOnly,undefined);assert.equal(f.field('node_id').value,'');assert.equal(f.field('all_nodes').checked,false);
    assert.equal(f.field('any_modulation').checked,true);assert.equal(f.requests.filter(r=>r.options&&r.options.method).length,0);
    assert.match(f.status(),/starting bounds/);
});
test('selected named bounds can be manually edited and only the reviewed custom values persist',async()=>{
    const band={...saved,freq_min_hz:433100000,freq_max_hz:434500000,signal_class:'*',node_id:'chosen-rf',source_detection_id:null};
    const f=fixture([{patterns:[],can_manage:true},band]);f.api.settings(f.db);await settle();
    f.field('named_rf_band').value='2';f.field('named_rf_band').fire('change');f.button('Review selected band').click();await settle();
    f.field('freq_min_mhz').value='433.1';f.field('freq_max_mhz').value='434.5';f.field('node_id').value='chosen-rf';f.submit();await settle();
    const request=f.requests.find(r=>r.options&&r.options.method==='POST');assert.ok(request);
    assert.deepEqual(JSON.parse(JSON.stringify(request.options.body)),{freq_min_hz:433100000,freq_max_hz:434500000,signal_class:'*',node_id:'chosen-rf',note:'ISM 433 range'});
});
for (const mapping of [null, {}, [{label:'broken',min:NaN,max:100}], [{label:'broken',min:100,max:99}], [{label:'broken',min:-1,max:100}], [{label:'same',min:1,max:2},{label:'same',min:3,max:4}]])test(`invalid named mapping refuses preset but retains manual custom route ${JSON.stringify(mapping)}`,async()=>{
    const f=fixture([{patterns:[],can_manage:true}],[],mapping);f.api.settings(f.db);await settle();
    assert.equal(f.field('named_rf_band'),undefined);assert.equal(f.button('Ignore FM broadcast range…'),undefined);
    f.button('Add custom frequency range').click();await settle();assert.equal(f.field('freq_min_mhz').value,'');assert.equal(f.field('all_nodes').checked,false);
    assert.equal(f.requests.filter(r=>r.options&&r.options.method).length,0);
});
test('invalid picker value never opens a range and viewer never gets band controls',async()=>{
    const f=fixture([{patterns:[],can_manage:true}]);f.api.settings(f.db);await settle();
    assert.equal(f.button('Review selected band').disabled,true);f.field('named_rf_band').value='999';f.field('named_rf_band').fire('change');assert.equal(f.button('Review selected band').disabled,true);
    f.button('Review selected band').click();assert.equal(f.field('freq_min_mhz'),undefined);
    const viewer=fixture([{patterns:[saved],can_manage:false}]);viewer.api.settings(viewer.db);await settle();assert.equal(viewer.field('named_rf_band'),undefined);assert.equal(viewer.button('Review selected band'),undefined);
});
test('failed named-range save keeps edited values and explicit scope for retry',async()=>{
    const f=fixture([{patterns:[],can_manage:true},new Error('Disk unavailable'),{...saved,signal_class:'*'}]);f.api.settings(f.db);await settle();f.field('named_rf_band').value='1';f.field('named_rf_band').fire('change');f.button('Review selected band').click();await settle();
    f.field('freq_min_mhz').value='110';f.field('node_id').value='rf-one';f.submit();await settle();
    assert.match(f.status(),/Disk unavailable/);assert.equal(f.field('freq_min_mhz').value,'110');assert.equal(f.field('node_id').value,'rf-one');assert.equal(f.field('all_nodes').checked,false);assert.equal(f.button('Save alert rule').disabled,false);
    f.submit();await settle();assert.equal(f.requests.filter(r=>r.options&&r.options.method==='POST').length,2);
});
test('band guidance explicitly keeps capture and separate Wi-Fi Bluetooth alerts unchanged',async()=>{
    const f=fixture([{patterns:[],can_manage:true}]);f.api.settings(f.db);await settle();const text=walk(f.body).map(n=>n.textContent).join(' ');
    assert.match(text,/RF alerts only/);assert.match(text,/Wi-Fi or Bluetooth protocol alerts/);assert.match(text,/does not stop capture/);
});

test('named picker has an explicit accessible label independent of option text',async()=>{
    const f=fixture([{patterns:[],can_manage:true}]);f.api.settings(f.db);await settle();
    const picker=f.field('named_rf_band');const label=walk(f.body).find(n=>n.tagName==='label'&&n.textContent==='Named RF band');
    assert.equal(label.attrs.for,picker.attrs.id);assert.ok(picker.attrs.id);assert.equal(label.children.length,0);
});
