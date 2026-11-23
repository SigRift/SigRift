/* The admin console's Advanced (WiFi and SDR anomaly scoring, rescore),
 * ML Advisor and Reports tabs (admin.js), driven through the controls of
 * templates/admin.html in the admin_dom.cjs stub DOM. */
const assert = require('node:assert/strict');
const test = require('node:test');
const { adminPage, noUnexpectedConsoleErrors, reply, assertCookieWrite, call } = require('./admin_dom.cjs');

test.afterEach(noUnexpectedConsoleErrors);

const lastToast = page => page.toasts().at(-1);

/* ------------------------------------------------------------------ */
/* Advanced: WiFi scoring                                              */
/* ------------------------------------------------------------------ */

const BALANCED = {
    novel_class: 0.22, rare_class: 0.12, low_confidence: 0.14, power_zscore: 0.13, snr_zscore: 0.10,
    timing_anomaly: 0.05, quiet_frequency: 0.04, iq_quality: 0.08, spectral_anomaly: 0.07, modulation_anomaly: 0.05,
};
const DEFAULTS = {
    wifi_anomaly_insert_threshold: 0.4, wifi_anomaly_alert_threshold: 0.7, wifi_anomaly_cooldown_seconds: 300,
    wifi_auto_snooze_hours: 24, wifi_dimension_weights: { beacon_rate: 0.6, new_bssid: 0.4 },
    rf_anomaly_insert_threshold: 0.3, rf_anomaly_alert_threshold: 0.7, rf_min_learning_detections: 300,
    rf_dimension_weights: BALANCED,
};
const CONFIG = {
    wifi_anomaly_insert_threshold: 0.45, wifi_dimension_weights: { beacon_rate: 0.5, new_bssid: 0.5 },
    rf_anomaly_insert_threshold: 0.35, rf_dimension_weights: BALANCED,
};

async function advancedTab({ config = CONFIG, defaults = DEFAULTS, routes = {} } = {}) {
    const page = await adminPage({
        routes: { 'GET /api/admin/detection-config': () => reply(200, { config, defaults }), ...routes },
    });
    await page.tab('advanced');
    return page;
}
const value = (page, id) => page.byId(id).value;
const hint = (page, id) => page.byId(id).textContent;
async function slide(page, id, to) {
    const input = page.byId(id);
    input.value = to;
    await page.input(input, to);
}

test('WiFi scoring: each field shows the saved value, else the default, with the default beside it', async () => {
    const page = await advancedTab();
    assert.deepEqual([page.byId('det-config-loading').style.display, page.byId('det-config-fields').style.display], ['none', '']);
    assert.deepEqual([value(page, 'det-wifi-insert-threshold'), hint(page, 'def-wifi-insert')], ['0.45', '(default: 0.4)']);
    assert.deepEqual([value(page, 'det-wifi-alert-threshold'), hint(page, 'def-wifi-alert')], ['0.7', '(default: 0.7)']);
    assert.deepEqual([value(page, 'det-wifi-critical-threshold'), hint(page, 'def-wifi-critical')], ['', ''], 'no value and no default');
    assert.deepEqual([value(page, 'det-wifi-cooldown'), hint(page, 'def-wifi-cooldown')], ['300', '(default: 300)']);
    const sliders = page.byId('wifi-weights-container').querySelectorAll('input[type=range]');
    assert.deepEqual(sliders.map(s => [s.id, s.value]), [['wifi-w-beacon_rate', '0.50'], ['wifi-w-new_bssid', '0.50']]);
    assert.deepEqual(page.byId('wifi-weights-container').querySelectorAll('label').map(l => l.textContent),
        ['beacon rate(default: 0.6)', 'new bssid(default: 0.4)']);
    const sum = page.byId('wifi-weight-sum');
    assert.equal(sum.textContent, '(sum: 1.00)');
    assert.equal(sum.querySelector('span').style.color, 'var(--accent-green)');

    await slide(page, 'wifi-w-beacon_rate', '0.7');
    assert.equal(page.byId('wifi-w-beacon_rate-val').textContent, '0.70');
    assert.equal(sum.textContent, '(sum: 1.20)');
    assert.equal(sum.querySelector('span').style.color, 'var(--accent-red)', 'weights that do not add up to 1 are flagged');
});

test('WiFi scoring: Save sends the typed fields as numbers with the slider weights', async () => {
    let refuse = false;
    const page = await advancedTab({ routes: { 'PUT /api/admin/detection-config': () => (refuse ? reply(422, { detail: 'threshold out of range' }) : reply(200, { config: {} })) } });
    page.byId('det-wifi-insert-threshold').value = '0.5';
    page.byId('det-wifi-cooldown').value = '600.9';
    page.byId('det-wifi-snooze-hours').value = '';
    await slide(page, 'wifi-w-beacon_rate', '0.65');
    await slide(page, 'wifi-w-new_bssid', '0.35');
    const button = page.byId('det-config-save-btn'), result = page.byId('det-config-result');
    button.click();
    assert.deepEqual([button.disabled, button.textContent], [true, 'Saving...']);
    await page.advance(0);
    // Fields left empty (no saved value and no default) are not sent.
    const [save] = page.writes();
    assert.deepEqual(call(save), ['PUT', '/api/admin/detection-config', {
        wifi_anomaly_insert_threshold: 0.5, wifi_anomaly_alert_threshold: 0.7, wifi_anomaly_cooldown_seconds: 600,
        wifi_dimension_weights: { beacon_rate: 0.65, new_bssid: 0.35 },
    }]);
    assertCookieWrite(save);
    assert.deepEqual([button.disabled, button.textContent], [false, 'Save WiFi Config']);
    assert.deepEqual([result.style.display, result.textContent], ['', 'Detection config saved.']);
    await page.advance(4000);
    assert.equal(result.style.display, 'none');

    refuse = true;
    await page.click(button);
    assert.deepEqual([result.style.display, result.textContent], ['', 'Failed: threshold out of range']);
    assert.deepEqual([button.disabled, button.textContent], [false, 'Save WiFi Config']);
});

test('WiFi scoring: Reset needs confirmation, sends the factory defaults and shows them', async () => {
    let answer = () => reply(200, { config: { wifi_anomaly_insert_threshold: 0.4 } });
    const page = await advancedTab({ routes: { 'PUT /api/admin/detection-config': () => answer() } });
    await page.click(page.byId('det-config-reset-btn'));
    assert.match(page.modal().textContent, /Reset WiFi scoring to factory defaults\?/);
    await page.click(page.button('Cancel'));
    assert.deepEqual(page.writes(), []);
    await page.click(page.byId('det-config-reset-btn'));
    await page.click(page.button('Reset'));
    assert.deepEqual(call(page.writes()[0]), ['PUT', '/api/admin/detection-config', {
        wifi_anomaly_insert_threshold: 0.4, wifi_anomaly_alert_threshold: 0.7, wifi_anomaly_cooldown_seconds: 300,
        wifi_auto_snooze_hours: 24, wifi_dimension_weights: { beacon_rate: 0.6, new_bssid: 0.4 },
    }]);
    assert.equal(value(page, 'det-wifi-insert-threshold'), '0.4');
    assert.deepEqual(page.byId('wifi-weights-container').querySelectorAll('input[type=range]').map(s => s.value), ['0.60', '0.40'],
        'the defaults are shown once reset');
    assert.equal(page.byId('det-config-result').textContent, 'WiFi config reset to defaults.');

    answer = () => reply(500, { detail: 'store is read-only' });
    await page.click(page.byId('det-config-reset-btn'));
    await page.click(page.button('Reset'));
    assert.equal(page.byId('det-config-result').textContent, 'Failed: store is read-only');
    assert.deepEqual(lastToast(page), { text: 'Reset failed: store is read-only', type: 'error', markup: 0 });
});

test('a scoring configuration the server cannot load is reported where the form would be', async () => {
    const page = await adminPage({ routes: { 'GET /api/admin/detection-config': () => reply(503) } });
    await page.tab('advanced');
    assert.equal(page.byId('det-config-loading').textContent, 'Failed to load detection config: HTTP 503');
    assert.equal(page.byId('det-config-fields').style.display, 'none');
    page.allowConsoleErrors(); // the failure is also logged for developers
});

test('a server without saved or default weights shows no sliders and a zero sum', async () => {
    const page = await advancedTab({ config: {}, defaults: {} });
    assert.equal(page.byId('wifi-weights-container').innerHTML, '');
    assert.equal(page.byId('wifi-weight-sum').textContent, '(sum: 0.00)');
    assert.deepEqual(page.byId('sdr-rf-weights-container').querySelectorAll('input[type=range]').map(s => s.value), Array(10).fill('0.00'));
    assert.equal(page.byId('sdr-weight-preset').value, 'custom');
});

/* ------------------------------------------------------------------ */
/* Advanced: SDR scoring                                               */
/* ------------------------------------------------------------------ */

const groupSums = page => [0, 1, 2, 3].map(g => page.byId('sdr-rf-w-group-' + g + '-sum').textContent);
const rfWeights = page => Object.fromEntries(page.byId('sdr-rf-weights-container').querySelectorAll('input[type=range]').map(s => [s.id.slice(9), s.value]));

test('SDR scoring: the RF weights are grouped, each group shows its sum, and a matching preset is recognised', async () => {
    const page = await advancedTab();
    assert.deepEqual([page.byId('sdr-config-loading').style.display, page.byId('sdr-config-fields').style.display], ['none', '']);
    assert.deepEqual([value(page, 'sdr-rf-insert-threshold'), hint(page, 'sdr-def-insert')], ['0.35', '(default: 0.3)']);
    assert.deepEqual([value(page, 'sdr-rf-learning-detections'), hint(page, 'sdr-def-learning')], ['300', '(default: 300)']);
    assert.deepEqual([value(page, 'sdr-rf-confidence-floor'), hint(page, 'sdr-def-conf-floor')], ['', '']);
    const container = page.byId('sdr-rf-weights-container');
    assert.deepEqual(container.querySelectorAll('.weight-group-header').map(h => h.textContent.replace(/\(.*\)/, '').trim()),
        ['▼ Signal Identity', '▼ Signal Characteristics', '▼ Behavioral Pattern', '▼ Signal Quality']);
    assert.deepEqual(groupSums(page), ['(0.48)', '(0.23)', '(0.09)', '(0.20)']);
    assert.equal(page.byId('sdr-rf-weight-sum').textContent, '(sum: 1.00)');
    assert.equal(page.byId('sdr-weight-preset').value, 'balanced');
    assert.equal(page.byId('sdr-rescore-btn').disabled, true, 'rescoring waits for a simulation');

    const header = container.querySelector('.weight-group-header');
    await page.click(header);
    assert.ok(page.byId('sdr-rf-w-group-0').classList.contains('collapsed'));
    await page.click(header);
    assert.ok(!page.byId('sdr-rf-w-group-0').classList.contains('collapsed'));
});

test('SDR scoring: choosing a preset sets its weights; moving a slider makes the weights custom', async () => {
    const page = await advancedTab();
    await page.change(page.byId('sdr-weight-preset'), 'novel_signal');
    assert.deepEqual(rfWeights(page), {
        novel_class: '0.30', rare_class: '0.18', low_confidence: '0.16', power_zscore: '0.08', snr_zscore: '0.06',
        timing_anomaly: '0.04', quiet_frequency: '0.05', iq_quality: '0.05', spectral_anomaly: '0.05', modulation_anomaly: '0.03',
    });
    assert.equal(page.byId('sdr-rf-w-novel_class-val').textContent, '0.30');
    assert.deepEqual(groupSums(page), ['(0.64)', '(0.14)', '(0.09)', '(0.13)']);
    assert.equal(page.byId('sdr-rf-weight-sum').textContent, '(sum: 1.00)');

    // A simulation enables rescoring; changing a weight invalidates it again.
    page.routes['POST /api/admin/simulate-rescore-rf'] = () => reply(200, { total: 1, priority_before: {}, priority_after: {} });
    await page.click(page.byId('sdr-simulate-btn'));
    assert.equal(page.byId('sdr-rescore-btn').disabled, false);
    await slide(page, 'sdr-rf-w-iq_quality', '0.25');
    assert.equal(page.byId('sdr-weight-preset').value, 'custom');
    assert.equal(page.byId('sdr-rf-w-iq_quality-val').textContent, '0.25');
    assert.deepEqual(groupSums(page)[3], '(0.33)');
    assert.equal(page.byId('sdr-rf-weight-sum').textContent, '(sum: 1.20)');
    assert.deepEqual([page.byId('sdr-rescore-btn').disabled, page.byId('sdr-rescore-btn').title], [true, 'Run simulation first']);
    assert.equal(page.byId('sdr-simulate-results').style.display, 'none', 'the stale simulation is hidden');

    await page.change(page.byId('sdr-weight-preset'), 'power_anomaly');
    assert.equal(rfWeights(page).power_zscore, '0.22');
    await slide(page, 'sdr-rf-w-power_zscore', '0.22');
    assert.equal(page.byId('sdr-weight-preset').value, 'power_anomaly', 'weights equal to a preset select it');
    await page.change(page.byId('sdr-weight-preset'), 'custom');
    assert.equal(rfWeights(page).power_zscore, '0.22', 'choosing Custom keeps the weights');
});

test('SDR scoring: Save sends the RF fields and weights and invalidates the simulation', async () => {
    let refuse = false;
    const page = await advancedTab({
        routes: {
            'PUT /api/admin/detection-config': () => (refuse ? reply(500) : reply(200, { config: { rf_anomaly_insert_threshold: 0.5, rf_dimension_weights: BALANCED } })),
            'POST /api/admin/simulate-rescore-rf': () => reply(200, { total: 0 }),
        },
    });
    await page.click(page.byId('sdr-simulate-btn'));
    page.byId('sdr-rf-insert-threshold').value = '0.5';
    page.byId('sdr-rf-confidence-floor').value = '';
    page.byId('sdr-rf-learning-detections').value = '450.7';
    await page.change(page.byId('sdr-weight-preset'), 'low_noise');
    const button = page.byId('sdr-config-save-btn'), result = page.byId('sdr-config-result');
    button.click();
    assert.deepEqual([button.disabled, button.textContent], [true, 'Saving...']);
    await page.advance(0);
    const save = page.writes().find(r => r.method === 'PUT');
    assert.deepEqual(save.body, {
        rf_anomaly_insert_threshold: 0.5, rf_anomaly_alert_threshold: 0.7, rf_min_learning_detections: 450,
        rf_dimension_weights: {
            novel_class: 0.18, rare_class: 0.06, low_confidence: 0.1, power_zscore: 0.16, snr_zscore: 0.14,
            timing_anomaly: 0.03, quiet_frequency: 0.03, iq_quality: 0.12, spectral_anomaly: 0.1, modulation_anomaly: 0.08,
        },
    });
    assertCookieWrite(save);
    assert.deepEqual([button.disabled, button.textContent], [false, 'Save SDR Config']);
    assert.equal(result.textContent, 'SDR scoring config saved.');
    assert.equal(page.byId('sdr-rescore-btn').disabled, true, 'a saved change needs a new simulation');
    await page.advance(4000);
    assert.equal(result.style.display, 'none');

    refuse = true;
    await page.click(button);
    assert.deepEqual([result.style.display, result.textContent], ['', 'Failed: HTTP 500']);
});

test('SDR scoring: Reset needs confirmation and sends the RF factory defaults', async () => {
    let answer = () => reply(200, { config: { rf_dimension_weights: BALANCED } });
    const page = await advancedTab({ routes: { 'PUT /api/admin/detection-config': () => answer() } });
    await page.change(page.byId('sdr-weight-preset'), 'novel_signal');
    await page.click(page.byId('sdr-config-reset-btn'));
    assert.match(page.modal().textContent, /Reset SDR scoring to factory defaults\?/);
    await page.key('Escape');
    assert.deepEqual(page.writes(), []);
    await page.click(page.byId('sdr-config-reset-btn'));
    await page.click(page.button('Reset'));
    assert.deepEqual(page.writes()[0].body, {
        rf_anomaly_insert_threshold: 0.3, rf_anomaly_alert_threshold: 0.7, rf_min_learning_detections: 300, rf_dimension_weights: BALANCED,
    });
    assert.equal(page.byId('sdr-weight-preset').value, 'balanced', 'the reset weights are shown');
    assert.equal(page.byId('sdr-config-result').textContent, 'SDR scoring reset to defaults.');
    await page.advance(4000);
    assert.equal(page.byId('sdr-config-result').style.display, 'none');

    answer = () => reply(403, {});
    await page.click(page.byId('sdr-config-reset-btn'));
    await page.click(page.button('Reset'));
    assert.deepEqual(page.redirects, ['/login?next=%2Fadmin'], 'a refused reset signs the admin out');
});

test('SDR scoring: a refused reset says why', async () => {
    const page = await advancedTab({ routes: { 'PUT /api/admin/detection-config': () => reply(409, { detail: 'rescore running' }) } });
    await page.click(page.byId('sdr-config-reset-btn'));
    await page.click(page.button('Reset'));
    assert.equal(page.byId('sdr-config-result').textContent, 'Failed: rescore running');
    assert.deepEqual(lastToast(page), { text: 'Reset failed: rescore running', type: 'error', markup: 0 });
});

/* ------------------------------------------------------------------ */
/* Advanced: simulate and rescore                                      */
/* ------------------------------------------------------------------ */

const SIMULATION = { total: 120, would_remove: 30, would_update: 50, unchanged: 40, remaining: 90,
    priority_before: { high: 20, low: 100 }, priority_after: { high: 15, medium: 5, low: 70 } };

test('Simulate Rescore shows what a rescore would change, can copy it, and only then allows rescoring', async () => {
    let answer = () => reply(200, SIMULATION);
    const page = await advancedTab({ routes: { 'POST /api/admin/simulate-rescore-rf': () => answer() } });
    const button = page.byId('sdr-simulate-btn'), status = page.byId('sdr-rescore-status'), results = page.byId('sdr-simulate-results');
    button.click();
    assert.deepEqual([button.disabled, button.textContent, status.textContent], [true, 'Simulating...', 'Calculating...']);
    await page.advance(0);
    assert.deepEqual([button.disabled, button.textContent, status.textContent], [false, 'Simulate Rescore', '']);
    assert.equal(results.style.display, '');
    assert.deepEqual(results.querySelectorAll('.sim-stat').map(s => s.textContent),
        ['Current: 120', 'Would remove: 30', 'Would update: 50', 'Unchanged: 40', 'Remaining: 90']);
    assert.deepEqual(results.querySelectorAll('tbody tr').map(tr => tr.children.map(td => td.textContent)),
        [['high', '20', '15'], ['low', '100', '70'], ['medium', '0', '5']]);
    assert.equal(page.byId('sdr-rescore-btn').disabled, false);

    const copy = page.byId('sdr-sim-copy-btn');
    await page.click(copy);
    assert.deepEqual(page.clipboard, [[
        'Rescore Simulation (dry run)', 'Current: 120 | Remove: 30 | Update: 50 | Unchanged: 40 | Remaining: 90', '',
        'Priority\tBefore\tAfter', 'high\t20\t15', 'low\t100\t70', 'medium\t0\t5',
    ].join('\n')]);
    assert.equal(copy.textContent, 'Copied!');
    await page.advance(2000);
    assert.equal(copy.textContent, 'Copy Results');

    answer = () => reply(500, { detail: 'scorer not ready' });
    await page.click(button);
    assert.deepEqual([status.textContent, status.style.color], ['Simulation failed: scorer not ready', 'var(--accent-red)']);
    assert.equal(results.style.display, 'none');
});

test('Rescore needs confirmation, reports what it changed, and needs a new simulation afterwards', async () => {
    let answer = () => reply(200, { updated: 3, removed: 2, total: 10 });
    const page = await advancedTab({
        routes: { 'POST /api/admin/simulate-rescore-rf': () => reply(200, SIMULATION), 'POST /api/admin/rescore-rf-anomalies': () => answer() },
    });
    const rescore = page.byId('sdr-rescore-btn'), status = page.byId('sdr-rescore-status');
    await page.click(page.byId('sdr-simulate-btn'));
    await page.click(rescore);
    assert.match(page.modal().textContent, /Anomalies below the insert threshold or confidence floor will be removed\./);
    await page.click(page.button('Cancel'));
    assert.deepEqual(page.writes().map(r => r.url), ['/api/admin/simulate-rescore-rf']);

    await page.click(rescore);
    await page.click(page.button('Rescore'));
    assert.deepEqual(call(page.writes()[1]), ['POST', '/api/admin/rescore-rf-anomalies', undefined]);
    assert.deepEqual([status.textContent, status.style.color], ['3 updated, 2 removed (of 10 total)', 'var(--accent-green)']);
    assert.equal(page.byId('sdr-simulate-results').style.display, 'none');
    assert.deepEqual([rescore.disabled, rescore.textContent], [true, 'Rescore Anomalies']);

    answer = () => reply(500, { detail: 'database is locked' });
    await page.click(page.byId('sdr-simulate-btn'));
    await page.click(rescore);
    await page.click(page.button('Rescore'));
    assert.deepEqual([status.textContent, status.style.color], ['Failed: database is locked', 'var(--accent-red)']);
    assert.deepEqual(lastToast(page), { text: 'Rescore failed: database is locked', type: 'error', markup: 0 });
    assert.equal(rescore.disabled, true);
});

/* ------------------------------------------------------------------ */
/* ML Advisor                                                          */
/* ------------------------------------------------------------------ */

const ADVISOR_URLS = ['/api/detections/distribution?hours=24', '/api/detections/anomalies/summary', '/api/training/runs', '/api/nodes/',
    '/api/spectrum/monitor/peaks?hours=24', '/api/metrics', '/api/detections/correlations/summary?hours=24', '/api/bluetooth/stats'];

async function advisor(data) {
    const routes = {};
    for (const url of ADVISOR_URLS) {
        routes['GET ' + url] = () => (url in data ? (data[url] instanceof Error ? reply(500) : reply(200, data[url])) : reply(500));
    }
    const page = await adminPage({ routes });
    await page.tab('ml-advisor');
    assert.deepEqual(page.requests.filter(r => ADVISOR_URLS.includes(r.url)), [], 'nothing is analysed until asked');
    const button = page.byId('ml-advisor-refresh');
    button.click();
    assert.deepEqual([button.disabled, button.textContent], [true, 'Analyzing...']);
    await page.advance(0);
    assert.deepEqual([button.disabled, button.textContent], [false, 'Analyze Platform']);
    return page;
}
const cards = page => page.byId('ml-advisor-metrics').querySelectorAll('.metric-card')
    .map(card => card.querySelector('.metric-value').textContent + ' ' + card.querySelector('.metric-label').textContent);
function advice(page, area) {
    const body = page.byId('ml-' + area + '-body');
    return {
        badge: page.byId('ml-' + area + '-badge').textContent,
        recs: body.querySelectorAll('strong').map((title, i) => body.querySelectorAll('span')[i].textContent + ' ' + title.textContent),
    };
}
const sorted = recs => [...recs].sort();

const classes = (...counts) => Object.fromEntries(counts.map((count, i) => ['class_' + i, count]));

test('Analyze Platform reads the platform data once asked and summarises it', async () => {
    const page = await advisor({
        '/api/detections/distribution?hours=24': { classes: classes(500, 500), total: 1000 },
        '/api/detections/anomalies/summary': { total_rf: 1500 },
        '/api/training/runs': { runs: [{}, {}] },
        '/api/nodes/': [{ node_id: 'a', status: 'active' }],
        '/api/metrics': { ingest: { detections_per_second: 4.26 } },
    });
    assert.deepEqual(page.requests.filter(r => ADVISOR_URLS.includes(r.url)).map(r => r.url), ADVISOR_URLS);
    assert.equal(page.byId('ml-advisor-empty').style.display, 'none');
    assert.deepEqual(cards(page).filter(c => !c.endsWith('Active Nodes')), ['2 Signal Classes (24h)', '1.0K Detections (24h)',
        '1.5K RF Anomalies', '2 Training Runs', '4.3/s Ingest Rate']);
});

test('every source the advisor reads may fail: it still advises, from empty data', async () => {
    const page = await advisor({});
    assert.deepEqual(cards(page), ['0 Signal Classes (24h)', '0 Detections (24h)', '0 RF Anomalies', '0 Training Runs',
        '0/0 Active Nodes', '-- Ingest Rate']);
    assert.deepEqual(sorted(advice(page, 'cls').recs), ['HIGH No hardware-captured training data', 'MEDIUM Expand signal taxonomy']);
    assert.deepEqual(advice(page, 'anom').recs, ['LOW Review 7-dimension anomaly scoring weights']);
    assert.deepEqual(sorted(advice(page, 'data').recs), ['LOW Bluetooth scanning not active', 'MEDIUM Limited frequency band coverage',
        'MEDIUM No spectrum sweep data']);
    assert.equal(advice(page, 'expand').badge, '6');
    assert.ok(!advice(page, 'expand').recs.some(r => /Quantize|Federated/.test(r)), 'no node-dependent advice without nodes');
});

test('classification advice: imbalance, taxonomy size, accuracy, hardware data and rare classes', async () => {
    const many = Object.fromEntries(Array.from({ length: 16 }, (_, i) => ['c' + i, 100]));
    for (const [name, dist, runs, expected] of [
        ['severe imbalance and low accuracy', { classes: { bpsk: 2100, fsk: 100 }, total: 2200 }, [{ best_val_accuracy: 0.71, data_source: 'synthetic' }],
            ['HIGH Model accuracy below 80%', 'HIGH No hardware-captured training data', 'HIGH Severe class imbalance detected', 'MEDIUM Expand signal taxonomy']],
        ['moderate imbalance, good accuracy, hardware data', { classes: { bpsk: 600, fsk: 100 }, total: 700 },
            [{ best_val_accuracy: 0.85, data_source: 'hardware-sdr' }, { best_val_accuracy: 0.5 }],
            ['MEDIUM Expand signal taxonomy', 'MEDIUM Model accuracy good but improvable', 'MEDIUM Moderate class imbalance']],
        ['a balanced wide taxonomy with an excellent model and a rare class', { classes: { ...many, rare: 1 }, total: 1601 },
            [{ best_val_accuracy: 0.95, data_source: 'hardware' }],
            ['HIGH Severe class imbalance detected', 'LOW Rare signal classes: rare']],
        ['a balanced wide taxonomy', { classes: many, total: 1600 }, [{ best_val_accuracy: 0.95, data_source: 'hardware' }], []],
    ]) {
        const page = await advisor({ '/api/detections/distribution?hours=24': dist, '/api/training/runs': { runs } });
        const { badge, recs } = advice(page, 'cls');
        assert.deepEqual(sorted(recs), expected, name);
        assert.equal(badge, String(expected.length), name);
        if (!expected.length) assert.equal(page.byId('ml-cls-body').textContent, 'No recommendations');
    }
});

test('anomaly advice: alert volume, dismissal rate and cross-node correlation', async () => {
    const nodes = n => Array.from({ length: n }, (_, i) => ({ node_id: 'n' + i, status: 'active' }));
    for (const [name, summary, corr, nodeList, expected] of [
        // 400 still active (3000 - 2600) is under the volume limit.
        ['mostly dismissed', { total_rf: 3000, dismissed_rf: 2600 }, {}, nodes(1),
            ['MEDIUM 80%+ anomalies dismissed — thresholds too sensitive']],
        ['a high active count from the server', { total_rf: 900, active_rf: 900 }, {}, [], ['HIGH High anomaly volume (900 active)']],
        ['very few anomalies on a correlated fleet', { total_rf: 4 }, { total_correlations_24h: 12, avg_nodes_per_correlation: 2.5 }, nodes(3),
            ['LOW Multi-node correlation active', 'LOW Very few anomalies — thresholds may be too high']],
        ['a fleet that never correlates', { total_rf: 50 }, { total_correlations_24h: 0 }, nodes(2), ['MEDIUM No cross-node correlations detected']],
    ]) {
        const page = await advisor({ '/api/detections/anomalies/summary': summary, '/api/detections/correlations/summary?hours=24': corr, '/api/nodes/': nodeList });
        const recs = advice(page, 'anom').recs.filter(r => r !== 'LOW Review 7-dimension anomaly scoring weights');
        assert.deepEqual(sorted(recs), sorted(expected), name);
        assert.equal(advice(page, 'anom').badge, String(expected.length + 1), name);
    }
});

test('data advice: node count, spectrum sweeps, Bluetooth, database size and band coverage', async () => {
    const page = await advisor({
        '/api/nodes/': [{ node_id: 'solo', status: 'active' }],
        '/api/spectrum/monitor/peaks?hours=24': { count: 7 },
        '/api/bluetooth/stats': { total_devices: 3 },
        '/api/metrics': { database: { db_size_mb: 2048.4 } },
        '/api/detections/distribution?hours=24': { classes: { 'lora-css': 5 }, total: 5 },
    });
    assert.deepEqual(sorted(advice(page, 'data').recs), ['HIGH Single-node deployment', 'LOW Limited spectrum peak data (7 peaks)',
        'MEDIUM Large database (2048 MB)']);
    for (const [name, dist, expected] of [['Zigbee alone', { zigbee: 1 }, false], ['WiFi OFDM alone', { 'wifi-ofdm': 1 }, false], ['neither', { bpsk: 1 }, true]]) {
        const other = await advisor({ '/api/detections/distribution?hours=24': { classes: dist, total: 1 }, '/api/spectrum/monitor/peaks?hours=24': { count: 50 },
            '/api/bluetooth/stats': { total_devices: 1 } });
        assert.equal(advice(other, 'data').recs.includes('MEDIUM Limited frequency band coverage'), expected, name);
        assert.ok(!advice(other, 'data').recs.some(r => /spectrum|Bluetooth/.test(r)), name);
    }
});

test('expansion advice adds edge quantisation for any node and federated learning from three nodes', async () => {
    const one = await advisor({ '/api/nodes/': [{ node_id: 'a' }] });
    assert.ok(advice(one, 'expand').recs.includes('MEDIUM Quantize model for edge inference'));
    assert.ok(!advice(one, 'expand').recs.includes('LOW Federated learning across edge nodes'));
    assert.equal(advice(one, 'expand').badge, '7');
    const three = await advisor({ '/api/nodes/': [{ node_id: 'a' }, { node_id: 'b' }, { node_id: 'c' }] });
    assert.ok(advice(three, 'expand').recs.includes('LOW Federated learning across edge nodes'));
    assert.equal(advice(three, 'expand').badge, '8');
});

test('the advisor lists high-priority recommendations first', async () => {
    const page = await advisor({});
    const order = { HIGH: 0, MEDIUM: 1, LOW: 2 };
    for (const area of ['cls', 'data', 'expand']) {
        const ranks = advice(page, area).recs.map(r => order[r.split(' ')[0]]);
        assert.deepEqual(ranks, [...ranks].sort((a, b) => a - b), area);
    }
});

test('the advisor counts nodes the bridge reports as active as online', async () => {
    const page = await advisor({ '/api/nodes/': [{ node_id: 'a', status: 'active' }, { node_id: 'b', status: 'active' }] });
    assert.ok(cards(page).includes('2/2 Active Nodes'));
    assert.ok(!advice(page, 'data').recs.some(r => /offline/.test(r)));
});

test('stale, offline and unknown nodes are not counted as active', async () => {
    const page = await advisor({ '/api/nodes/': ['active', 'stale', 'offline', 'unknown'].map((status, i) => ({ node_id: 'n' + i, status })) });
    assert.ok(cards(page).includes('1/4 Active Nodes'), cards(page).join(' | '));
    assert.ok(advice(page, 'data').recs.includes('MEDIUM 3 node(s) offline'));
});

test('recommendations of each priority sort high, medium, low; an unknown priority sorts last', async () => {
    const page = await adminPage({});
    const recs = ['low', 'odd', 'medium', 'high', 'low', 'high'].map((priority, i) => ({ priority, title: priority + i, desc: '', impact: '' }));
    const holder = page.doc.createElement('div');
    holder.innerHTML = page.context.AdminPanel.prototype._renderRecommendations.call(null, recs);
    assert.deepEqual(holder.querySelectorAll('strong').map(title => title.textContent), ['high3', 'high5', 'medium2', 'low0', 'odd1', 'low4']);
});

/* ------------------------------------------------------------------ */
/* Reports                                                             */
/* ------------------------------------------------------------------ */

async function reportsTab(answer, storage, cookie) {
    const page = await adminPage({ storage, cookie, routes: { 'GET /api/reports/generate': () => answer() } });
    await page.tab('reports');
    page.saved = [];
    page.doc.body.addEventListener('click', event => { if (event.target.localName === 'a') page.saved.push(event.target.getAttribute('download')); });
    return page;
}

test('generating a report downloads the file the server names, for the chosen period, format and sections', async () => {
    const page = await reportsTab(() => new Response('{"report":1}', {
        status: 200, headers: { 'content-type': 'application/json', 'content-disposition': 'attachment; filename="sigrift-report-168h.json"' },
    }));
    page.byId('report-hours').value = '168';
    page.byId('report-format').value = 'json';
    page.doc.querySelector('.report-section[value="spectrum"]').checked = false;
    page.byId('generate-report-btn').click();
    assert.deepEqual([page.byId('report-status').style.display, page.byId('report-status-text').textContent], ['', 'Generating report...']);
    await page.advance(0);
    const request = page.requests.at(-1);
    assert.equal(request.url, '/api/reports/generate?hours=168&format=json&sections=detections%2Canomalies%2Cnodes%2Calerts');
    assert.equal(request.credentials, 'same-origin');
    assert.deepEqual(page.saved, ['sigrift-report-168h.json']);
    assert.equal(await page.blobs[0].text(), '{"report":1}');
    assert.equal(page.byId('report-status-text').textContent, 'Report downloaded: sigrift-report-168h.json');
});

test('a report without a server file name is saved as report.<format>; no section chosen means every section', async () => {
    const page = await reportsTab(() => new Response('<html></html>', { status: 200, headers: { 'content-type': 'text/html' } }),
        { bridge_session_token: 'tok' }, '');
    for (const box of page.doc.querySelectorAll('.report-section')) box.checked = false;
    await page.click(page.byId('generate-report-btn'));
    const request = page.requests.at(-1);
    assert.equal(request.url, '/api/reports/generate?hours=24&format=html&sections=detections%2Canomalies%2Cspectrum%2Cnodes%2Calerts');
    assert.equal(request.headers['X-Session-Token'], 'tok');
    assert.deepEqual(page.saved, ['report.html']);
});

test('a refused report shows the server reason and downloads nothing', async () => {
    const page = await reportsTab(() => reply(422, { detail: 'hours must be at most 720' }), { bridge_admin_key: 'adm' }, '');
    await page.click(page.byId('generate-report-btn'));
    assert.equal(page.requests.at(-1).headers['X-API-Key'], 'adm');
    assert.equal(page.byId('report-status-text').textContent, 'Failed: hours must be at most 720');
    assert.deepEqual(page.saved, []);
    page.routes['GET /api/reports/generate'] = () => reply(500, {});
    await page.click(page.byId('generate-report-btn'));
    assert.equal(page.byId('report-status-text').textContent, 'Failed: Report generation failed');
});

test('the downloaded report\'s name is shown as the server sent it', async () => {
    const page = await reportsTab(() => new Response('x', { status: 200, headers: { 'content-disposition': 'attachment; filename="R&D.html"' } }));
    await page.click(page.byId('generate-report-btn'));
    assert.equal(page.byId('report-status-text').textContent, 'Report downloaded: R&D.html');
});

test('a scoring change refused without an explanation reports its HTTP status', async () => {
    const page = await advancedTab({
        routes: {
            'PUT /api/admin/detection-config': () => reply(500),
            'POST /api/admin/simulate-rescore-rf': () => reply(500),
        },
    });
    await page.click(page.byId('det-config-save-btn'));
    assert.equal(page.byId('det-config-result').textContent, 'Failed: HTTP 500');
    await page.click(page.byId('det-config-reset-btn'));
    await page.click(page.button('Reset'));
    assert.deepEqual(lastToast(page), { text: 'Reset failed: HTTP 500', type: 'error', markup: 0 });
    await page.click(page.byId('sdr-config-reset-btn'));
    await page.click(page.button('Reset'));
    assert.equal(page.byId('sdr-config-result').textContent, 'Failed: HTTP 500');
    await page.click(page.byId('sdr-simulate-btn'));
    assert.equal(page.byId('sdr-rescore-status').textContent, 'Simulation failed: HTTP 500');
    assert.equal(page.byId('sdr-rescore-btn').disabled, true, 'a failed simulation does not allow rescoring');
});

test('a rescore refused without an explanation reports its HTTP status', async () => {
    const page = await advancedTab({
        routes: { 'POST /api/admin/simulate-rescore-rf': () => reply(200, SIMULATION), 'POST /api/admin/rescore-rf-anomalies': () => reply(500) },
    });
    await page.click(page.byId('sdr-simulate-btn'));
    await page.click(page.byId('sdr-rescore-btn'));
    await page.click(page.button('Rescore'));
    assert.equal(page.byId('sdr-rescore-status').textContent, 'Failed: HTTP 500');
    assert.deepEqual(lastToast(page), { text: 'Rescore failed: HTTP 500', type: 'error', markup: 0 });
});
