import { test } from 'node:test';
import assert from 'node:assert/strict';

globalThis.location = { search: '' };
const storage = new Map();
globalThis.sessionStorage = { getItem: (key) => storage.get(key) || null, removeItem: (key) => storage.delete(key) };
const { api } = await import('../js/api-client.js');
const { miningWorkState, candidateMetrics } = await import('../js/mining-work.js');
const response = (status, data) => ({ status, ok: status >= 200 && status < 300, json: async () => data });

test('a rejected candidate read remains an authorization failure, not absent work', async () => {
  globalThis.fetch = async () => response(403, { reason: 'invalid.api-key', detail: null });
  const result = await api.miningCandidate();
  assert.equal(result.status, 403);
  assert.equal(result.reason, 'invalid.api-key');
  assert.equal(miningWorkState(result).label, 'Authorization required');
  assert.equal(miningWorkState(result).candidate, undefined);
  assert.equal(miningWorkState(result).authorize, true);
});

test('preview, configuration, transient and transport failures stay distinct', async () => {
  assert.equal(miningWorkState({ status: 403, reason: 'preview-read-only' }).label, 'Hidden in design preview');
  assert.equal(miningWorkState({ status: 403, reason: 'api-key-not-configured' }).label, 'API key not configured');
  globalThis.fetch = async () => response(503, { reason: 'unavailable', detail: 'reward key pending: wallet not initialized' });
  const unavailable = miningWorkState(await api.miningCandidate());
  assert.equal(unavailable.label, 'Candidate not ready');
  assert.match(unavailable.detail, /reward key pending/);
  globalThis.fetch = async () => { throw new Error('offline'); };
  assert.equal(miningWorkState(await api.miningCandidate()).label, 'Candidate request failed');
  globalThis.fetch = async () => response(200, null);
  assert.equal(miningWorkState(await api.miningCandidate()).candidate, undefined);
});

test('valid work is available independently of mempool transaction counts', async () => {
  const work = { msg: 'ab'.repeat(32), h: 101, pk: '02' + 'cd'.repeat(32), b: 1e60, template_seq: 0, clean_jobs: false };
  globalThis.fetch = async () => response(200, work);
  const result = await api.miningCandidate();
  assert.equal(miningWorkState(result).label, 'Candidate available');
  assert.deepEqual(miningWorkState(result).candidate, work);
});

test('startup fresh-block wait is distinct from missing work or an index backlog', async () => {
  globalThis.fetch = async () => response(503, { reason: 'unavailable', detail: 'mining not available: waiting for a recent block after startup (headers=1881253 applied=1881253)' });
  const state = miningWorkState(await api.miningCandidate());
  assert.equal(state.label, 'Waiting for a fresh block');
  assert.equal(state.tone, 'neutral');
  assert.match(state.detail, /starts automatically/);
  assert.match(state.detail, /search indexing and an empty mempool do not block it/);
  assert.equal(state.candidate, undefined);
  assert.equal(miningWorkState({ status: 503, detail: 'node still catching up' }).label, 'Candidate not ready');
});

test('clearing authorization invalidates an in-flight candidate response', async () => {
  storage.set('ergo.apikey', 'test-key');
  let finish;
  globalThis.fetch = (_path, options) => {
    assert.equal(options.headers.api_key, 'test-key');
    return new Promise((resolve) => { finish = resolve; });
  };
  const pending = api.miningCandidate();
  storage.delete('ergo.apikey');
  finish(response(200, { msg: 'ab'.repeat(32), h: 101 }));
  assert.equal(await pending, null);
});

test('candidate metrics retain exact fees and distinguish emission-only zero selection from missing fields', () => {
  assert.equal(candidateMetrics({ msg: 'old-node' }), null);
  const metrics = candidateMetrics({ metrics: {
    selected_transaction_count: 0, transaction_count: 1, fees_nano_erg: '9007199254740993',
    transactions_size_bytes: 512, max_block_size_bytes: 1000000, validation_cost: 450, max_block_cost: 1000000,
  } });
  assert.equal(metrics.selected, 0);
  assert.equal(metrics.total, 1);
  assert.equal(metrics.fees, 9007199254740993n);
  assert.equal(metrics.cost, 450);
  assert.equal(metrics.size, 512);
  const missing = candidateMetrics({ metrics: { fees_nano_erg: 9007199254740993, transaction_count: null, selected_transaction_count: null } });
  assert.equal(missing.selected, null);
  assert.equal(missing.total, null);
  assert.equal(missing.fees, null);
  assert.equal(missing.cost, null);
  assert.equal(candidateMetrics({ metrics: { selected_transaction_count: 9, transaction_count: 1 } }).selected, null);
});
