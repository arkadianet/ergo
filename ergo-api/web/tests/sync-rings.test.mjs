import { test } from 'node:test';
import assert from 'node:assert/strict';
import { syncLayers } from '../js/sync-rings.js';

const ready = { reachable: true, status: { sync_state: 'at_tip', best_full_block_height: 100, best_header_height: 100 }, sync: { headers_chain_synced: true }, indexer: { status: 'caughtUp', indexedHeight: 100, fullHeight: 100 } };

test('the three bands only form a ready ring when all stages are ready', () => {
  assert.deepEqual(syncLayers(ready).map((r) => r.state), ['done', 'done', 'done']);
  const indexing = syncLayers({ ...ready, indexer: { status: 'syncing', indexedHeight: 80, fullHeight: 100 } });
  assert.equal(indexing[2].percent, 80);
  assert.equal(indexing[2].state, 'progress');
  assert.equal(indexing[2].text, '80.00%');
});

test('header discovery is unknown and index progress uses applied blocks', () => {
  const layers = syncLayers({ ...ready, status: { sync_state: 'syncing', best_header_height: 200, best_full_block_height: 100 }, sync: { headers_chain_synced: false }, indexer: { status: 'syncing', indexedHeight: 90, fullHeight: 100 } });
  assert.equal(layers[0].percent, null);
  assert.equal(layers[0].text, 'Discovering');
  assert.equal(layers[1].percent, 50);
  assert.equal(layers[2].percent, 90);
  assert.equal(syncLayers({})[1].percent, null);
});

test('stale, disabled, halted and repairing stages never claim completion', () => {
  assert.ok(syncLayers({ ...ready, reachable: false }).every((r) => r.state === 'stale'));
  assert.equal(syncLayers({ ...ready, identity: { extra_index_enabled: false } })[2].state, 'disabled');
  assert.equal(syncLayers({ ...ready, indexerHealth: { status: 'halted' } })[2].state, 'error');
  assert.equal(syncLayers({ ...ready, indexerHealth: { repair: { pending: true } } })[2].state, 'repair');
  assert.equal(syncLayers({ ...ready, status: { ...ready.status, apply_wedged: true } })[1].state, 'error');
  assert.notEqual(syncLayers({ ...ready, status: { ...ready.status, sync_state: 'syncing' } })[1].state, 'done');
});

test('rounding never turns incomplete measured progress into 100 percent', () => {
  const layers = syncLayers({ ...ready, indexer: { status: 'syncing', indexedHeight: 999999, fullHeight: 1000000 } });
  assert.equal(layers[2].text, '99.99%');
});

test('the block ring recovers only after applied blocks pass the rejection height', () => {
  const status = { ...ready.status, last_block_apply_error: { height: 100, age_ms: 10_800_000 } };
  assert.equal(syncLayers({ ...ready, status })[1].state, 'error');
  status.best_header_height = 101;
  assert.equal(syncLayers({ ...ready, status })[1].state, 'error');
  status.best_full_block_height = 101;
  assert.equal(syncLayers({ ...ready, status })[1].state, 'done');
  assert.equal(syncLayers({ ...ready, status: { ...status, apply_wedged: true } })[1].state, 'error');
  assert.equal(syncLayers({ ...ready, status, reachable: false })[1].state, 'stale');
});
