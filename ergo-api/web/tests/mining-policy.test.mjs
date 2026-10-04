import { test } from 'node:test';
import assert from 'node:assert/strict';

globalThis.location = { search: '' };
const storage = new Map();
globalThis.sessionStorage = { getItem: (key) => storage.get(key) || null, removeItem: (key) => storage.delete(key) };
const { policyDraft, policyRequest } = await import('../js/mining-policy.js');
const form = (overrides = {}) => ({ elements: Object.fromEntries(Object.entries({
  rent_cost: '93.75', rent_size: '93.75', private_cost: '10', private_size: '10',
  required: '', excluded: '', bundles: '', tokens: 'preserve', ...overrides,
}).map(([key, value]) => [key, { value }])) });

test('budget percentages and ordered required bundles build exact integer policy', () => {
  const id = 'AB'.repeat(32);
  const other = 'cd'.repeat(32);
  const policy = policyDraft(form({ bundles: `${id} ${other}` }));
  assert.equal(policy.rent_max_cost_basis_points, 9375);
  assert.equal(policy.private_reserved_size_basis_points, 1000);
  assert.deepEqual(policy.required_bundles, [[id.toLowerCase(), other]]);
  assert.equal(policy.rent_token_policy, 'preserve');
});

test('invalid percentages, malformed IDs and contradictory requirements reject before sending', () => {
  assert.throws(() => policyDraft(form({ private_cost: '101' })), /percentages/);
  assert.throws(() => policyDraft(form({ rent_size: '' })), /percentages/);
  assert.throws(() => policyDraft(form({ required: 'not-a-tx-id' })), /64 hexadecimal/);
  assert.throws(() => policyDraft(form({ required: 'AB'.repeat(32), excluded: 'ab'.repeat(32) })), /also be excluded/);
});

test('an authorization change discards an in-flight policy response', async () => {
  storage.set('ergo.apikey', 'operator-key');
  let finish;
  globalThis.fetch = (_path, options) => {
    assert.equal(options.headers.api_key, 'operator-key');
    return new Promise((resolve) => { finish = resolve; });
  };
  const pending = policyRequest();
  storage.delete('ergo.apikey');
  finish({ ok: true, status: 200, json: async () => policyDraft(form()) });
  assert.equal((await pending).stale, true);
});

test('policy API failures retain the node explanation', async () => {
  storage.set('ergo.apikey', 'operator-key');
  globalThis.fetch = async () => ({ ok: false, status: 400, json: async () => ({ error: { reason: 'bad_request', detail: 'required ID conflicts with exclusion' } }) });
  assert.equal((await policyRequest('PUT', {})).detail, 'required ID conflicts with exclusion');
});
