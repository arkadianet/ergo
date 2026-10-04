import { test } from 'node:test';
import assert from 'node:assert/strict';

globalThis.location = { search: '' };
const storage = new Map();
globalThis.sessionStorage = { getItem: (key) => storage.get(key) || null, removeItem: (key) => storage.delete(key) };
const { api } = await import('../js/api-client.js');
const { matchesTemplate, inspectorMessage, exclusionLabel, isUnmetRequirement } = await import('../js/mining-inspector.js');
const response = (status, data) => ({ status, ok: status >= 200 && status < 300, text: async () => JSON.stringify(data), json: async () => data });

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
