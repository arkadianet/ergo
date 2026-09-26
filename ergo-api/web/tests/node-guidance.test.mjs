import { test } from 'node:test';
import assert from 'node:assert/strict';
import { nodeGuidance } from '../js/node-guidance.js';

const ready = { reachable: true, status: { sync_state: 'at_tip', peer_count: 10 }, indexer: { status: 'caughtUp' }, identity: { extra_index_enabled: true } };

test('block sync and search readiness are separate', () => {
  assert.equal(nodeGuidance(ready).title, 'Ready to explore');
  const indexing = nodeGuidance({ ...ready, indexer: { status: 'syncing' } });
  assert.equal(indexing.title, 'Chain search is catching up');
  assert.equal(indexing.destination, 'explorer');
  assert.notEqual(nodeGuidance({ ...ready, indexer: null }).tone, 'ok');
  assert.equal(nodeGuidance({ ...ready, identity: { extra_index_enabled: false } }).title, 'Search index is disabled');
});

test('stale and missing data never claim readiness', () => {
  assert.equal(nodeGuidance({ ...ready, reachable: false }).title, 'Reconnect to your node');
  assert.equal(nodeGuidance({ ...ready, status: null }).title, 'Getting a live picture');
  assert.notEqual(nodeGuidance({ ...ready, status: { sync_state: 'future_state' } }).tone, 'ok');
  assert.notEqual(nodeGuidance({ ...ready, indexer: { status: 'future_state' } }).tone, 'ok');
});

test('reported issues take precedence over at-tip or ready index state', () => {
  for (const issue of [{ sync_wedged: true }, { apply_wedged: true }, { last_storage_error: 'disk full' }, { last_block_apply_error: { height: 123 } }, { shadow: { diverged: true } }]) {
    const guidance = nodeGuidance({ ...ready, status: { ...ready.status, ...issue } });
    assert.equal(guidance.tone, 'error');
    assert.equal(guidance.destination, 'diagnostics');
  }
  assert.equal(nodeGuidance({ ...ready, indexerHealth: { status: 'halted' } }).tone, 'error');
  assert.equal(nodeGuidance({ ...ready, indexer: { status: 'halted' } }).tone, 'error');
  assert.equal(nodeGuidance({ ...ready, indexerHealth: { repair: { pending: true } } }).tone, 'warn');
  assert.equal(nodeGuidance({ ...ready, indexerHealth: { repair: { skipped: 2 } } }).tone, 'warn');
});

test('next steps follow the cause instead of suggesting destructive recovery', () => {
  assert.equal(nodeGuidance({ ...ready, status: { sync_state: 'at_tip', peer_count: 0 } }).destination, 'peers');
  assert.equal(nodeGuidance({ ...ready, status: { sync_state: 'stalled', peer_count: 4 } }).destination, 'peers');
  assert.equal(nodeGuidance({ ...ready, status: { sync_state: 'syncing', peer_count: 4 } }).tone, 'neutral');
  assert.equal(nodeGuidance({ ...ready, status: { sync_state: 'syncing', peer_count: 4, bootstrap: {} } }).title, 'Bootstrap is still running');
  assert.equal(nodeGuidance({ ...ready, status: { sync_state: 'syncing', peer_count: 4, bootstrap: { popow_phase: 'abandoned' } } }).title, 'Ordinary header sync is continuing');
  assert.equal(nodeGuidance({ ...ready, identity: { verify_transactions: false } }).tone, 'warn');
});
