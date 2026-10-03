import { test } from 'node:test';
import assert from 'node:assert/strict';

globalThis.location = { search: '' };
globalThis.sessionStorage = { getItem: () => null, removeItem() {} };
const { lookupJson } = await import('../js/api-client.js');
const { loadTransaction } = await import('../js/transaction-source.js');
const response = (status, data) => ({ status, ok: status >= 200 && status < 300, json: async () => data, clone() { return this; } });

test('entity absence requires 404; readiness, authorization, transport and malformed responses fail explicitly', async () => {
  globalThis.fetch = async () => response(404, {});
  assert.equal(await lookupJson('/entity'), null);
  for (const status of [403, 500, 503]) {
    globalThis.fetch = async () => response(status, { reason: 'unavailable' });
    await assert.rejects(lookupJson('/entity'), (e) => e.status === status);
  }
  globalThis.fetch = async () => { throw new Error('offline'); };
  await assert.rejects(lookupJson('/entity'), (e) => e.status === 0);
  globalThis.fetch = async () => ({ status: 200, ok: true, json: async () => { throw new Error('bad JSON'); } });
  await assert.rejects(lookupJson('/entity'), /invalid JSON/);
  globalThis.fetch = async () => response(200, null);
  await assert.rejects(lookupJson('/entity'), /invalid JSON/);
});

test('transaction status requires a source response, including when another source fails', async () => {
  const values = [null, null, null];
  const read = async (path) => {
    const n = path.startsWith('/blockchain') ? 0 : path.startsWith('/transactions') ? 1 : 2;
    if (values[n] instanceof Error) throw values[n];
    return values[n];
  };
  assert.equal((await loadTransaction('id', read)).status, 'absent');
  values[0] = new Error('index unavailable');
  assert.equal((await loadTransaction('id', read)).status, 'unavailable');
  values[2] = { inputs: [], outputs: [] };
  assert.equal((await loadTransaction('id', read)).status, 'unknown');
  values[1] = { id: 'id' };
  assert.equal((await loadTransaction('id', read)).status, 'unconfirmed');
  values[0] = { blockId: 'block' };
  assert.equal((await loadTransaction('id', read)).status, 'confirmed');
  values[0] = null; values[1] = new Error('pool failed');
  assert.equal((await loadTransaction('id', read)).status, 'unknown');
});
