import { test } from 'node:test';
import assert from 'node:assert/strict';

globalThis.location = { search: '' };
const storage = new Map();
globalThis.sessionStorage = { getItem: (key) => storage.get(key) || null, removeItem: (key) => storage.delete(key) };
const { api } = await import('../js/api-client.js');
const { matchesTemplate, inspectorMessage, exclusionLabel, isUnmetRequirement, emissionRows, createMiningInspector } = await import('../js/mining-inspector.js');
const response = (status, data) => ({ status, ok: status >= 200 && status < 300, text: async () => JSON.stringify(data), json: async () => data });

// Inert elements: these tests count downloads, not browser layout.
class FakeElement {
  constructor(tag) { this.tagName = tag; this.children = []; this.style = {}; this.dataset = {}; this.attributes = {}; this.classList = { add() {}, remove() {}, toggle() {} }; this.textContent = ''; this.value = ''; }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this.children = nodes; }
  setAttribute(name, value) { this.attributes[name] = value; }
  addEventListener() {}
  querySelector() { return null; }
  contains() { return false; }
}
globalThis.Node = FakeElement;
globalThis.document = { createElement: (tag) => new FakeElement(tag), activeElement: null };
globalThis.CSS = { escape: String };
const report = (seq) => ({
  msg: 'ab'.repeat(32), template_seq: seq, parent_id: 'cd'.repeat(32), height: 10, status: 'current', published_at_ms: 1, age_ms: 0,
  build_reason: 'Tip', build_mode: 'enriched', metrics: {}, votes: [0, 0, 0], extensions: [], transactions: [], exclusions: [], policy_revision: 0, operator_generation: 0,
  rewards: { emission_nano_erg: '0', emission_gross_nano_erg: '0', reemission_obligation_nano_erg: '0', fees_nano_erg: '0', rent_nano_erg: '0', total_nano_erg: '0', outputs: [] },
  rent: { scanned_boxes: 0, selected_boxes: 0, recreated_boxes: 0, consumed_boxes: 0, skipped_to_preserve_tokens: 0, collected_nano_erg: '0', recovered_tokens: [], burned_tokens: [], claims: [] },
});
const historyReport = { retention: 16, retained_templates: [], outcomes: [], resets_on_restart: false, journal_error: null, chain_tip: null };

test('candidate inspection requires exact work ID and publish sequence', () => {
  const current = { msg: 'ab'.repeat(32), template_seq: 5 };
  assert.equal(matchesTemplate({ ...current }, current), true);
  assert.equal(matchesTemplate({ ...current, template_seq: 4 }, current), false);
  assert.equal(matchesTemplate({ ...current, msg: 'cd'.repeat(32) }, current), false);
  assert.equal(matchesTemplate(null, current), false);
});

test('inspection distinguishes authorization and eviction from an empty template', () => {
  assert.match(inspectorMessage({ status: 403 }), /Authorize/);
  assert.match(inspectorMessage({ status: 404 }), /no longer retained/);
  assert.match(inspectorMessage({ status: 503, data: { detail: 'No current template' } }), /No current template/);
});

test('unmet requirements read as required transactions left out of work', () => {
  assert.equal(isUnmetRequirement({ reason: 'required_unavailable' }), true);
  assert.equal(isUnmetRequirement({ reason: 'cost_budget' }), false);
  assert.match(exclusionLabel('required_unavailable'), /^Required, not included: not in the mempool or private queue/);
  assert.match(exclusionLabel('required_excluded_ancestor'), /^Required, not included: depends on a transaction your policy excludes/);
  assert.match(exclusionLabel('required_input_unavailable'), /^Required, not included: an input is spent/);
  assert.match(exclusionLabel('required_final_fee_or_section_budget'), /^Required, not included: trimmed/);
  assert.equal(exclusionLabel('input_conflict'), 'An input is already spent in this block');
  assert.equal(exclusionLabel('required_future_reason'), 'Required, not included: future reason');
});

test('an EIP-27 reward box shows its value, the re-emission owed and the emission kept', () => {
  assert.deepEqual(emissionRows({ emission_nano_erg: '3000000000', emission_gross_nano_erg: '12000000000', reemission_obligation_nano_erg: '9000000000' }), [
    ['Emission reward box', '12.0 ERG'],
    ['Owed to re-emission when spent (EIP-27)', '−9.0 ERG'],
    ['Emission kept', '3.0 ERG'],
  ]);
  assert.deepEqual(emissionRows({ emission_nano_erg: '67500000000', emission_gross_nano_erg: '67500000000', reemission_obligation_nano_erg: '0' }), [['Emission', '67.5 ERG']]);
  assert.deepEqual(emissionRows({ emission_nano_erg: '12000000000' }), [['Emission', '12.0 ERG']]);
});

test('candidate selector and operator key reach the authenticated details API', async () => {
  storage.set('ergo.apikey', 'operator-key');
  globalThis.fetch = async (path, options) => {
    assert.equal(path, `/api/v1/mining/candidate-details?msg=${'ab'.repeat(32)}&template_seq=9`);
    assert.equal(options.headers.api_key, 'operator-key');
    return response(200, { msg: 'ab'.repeat(32), template_seq: 9 });
  };
  assert.equal((await api.miningCandidateDetails('ab'.repeat(32), 9)).data.template_seq, 9);
});

test('cleared authorization discards in-flight inventory and history responses', async () => {
  for (const request of [() => api.miningCandidateDetails('ab'.repeat(32), 9), () => api.miningHistory()]) {
    storage.set('ergo.apikey', 'operator-key');
    let finish;
    globalThis.fetch = () => new Promise((resolve) => { finish = resolve; });
    const pending = request();
    storage.delete('ergo.apikey');
    finish(response(200, { private: 'contents' }));
    const result = await pending;
    assert.equal(result.ok, false);
    assert.equal(result.data, null);
  }
});

test('refreshing the same work does not download its report again', async () => {
  storage.set('ergo.apikey', 'operator-key');
  const downloads = [];
  let failing = false;
  globalThis.fetch = async (path) => {
    downloads.push(path);
    if (path === '/api/v1/mining/history') return response(200, historyReport);
    if (failing) return response(503, { error: { reason: 'candidate_unavailable' } });
    return response(200, report(Number(new URL(path, 'http://node').searchParams.get('template_seq'))));
  };
  const work = (seq) => ({ ok: true, status: 200, data: { msg: 'ab'.repeat(32), template_seq: seq } });
  const inspector = createMiningInspector(new FakeElement('div'));
  await inspector.refresh(work(5));
  assert.equal(downloads.length, 2, 'the report and history are downloaded once');
  await Promise.all([inspector.refresh(work(5)), inspector.refresh(work(5))]);
  assert.equal(downloads.length, 2, 'unchanged work is not downloaded again');
  await inspector.refresh(work(6));
  assert.equal(downloads.length, 4, 'new work is downloaded');
  failing = true;
  await inspector.refresh(work(7));
  await inspector.refresh(work(7));
  assert.equal(downloads.length, 8, 'a failed read is retried on the next refresh');
});

test('a download in flight is not repeated by another refresh', async () => {
  storage.set('ergo.apikey', 'operator-key');
  const downloads = [];
  const finishers = [];
  globalThis.fetch = (path) => {
    downloads.push(path);
    return new Promise((resolve) => finishers.push(() => resolve(path === '/api/v1/mining/history' ? response(200, historyReport) : response(200, report(9)))));
  };
  const work = { ok: true, status: 200, data: { msg: 'ab'.repeat(32), template_seq: 9 } };
  const inspector = createMiningInspector(new FakeElement('div'));
  const first = inspector.refresh(work);
  const second = inspector.refresh(work);
  assert.equal(downloads.length, 2);
  for (const finish of finishers) finish();
  await Promise.all([first, second]);
  assert.equal(downloads.length, 2);
});
