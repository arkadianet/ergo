import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mempoolView, readIndexerCapability, indexStatusCopy, ENABLE_MINING } from '../js/capabilities.js';

test('configured disabled, enabled empty and unknown mempool states remain distinct', () => {
  const disabled = mempoolView({ mempool_enabled: false }, 'at_tip');
  assert.equal(disabled.disabled, true);
  assert.match(disabled.title, /disabled/i);
  assert.doesNotMatch(disabled.copy, /will appear/);
  // `[mempool]` rejects unknown keys; its switch is `disabled`.
  assert.match(disabled.copy, /disabled = false in the \[mempool\]/);
  assert.doesNotMatch(disabled.copy, /enabled = true/);
  assert.match(disabled.copy, /--mempool-disabled/);
  assert.match(disabled.copy, /state_type = "digest" or verify_transactions = false/);
  assert.match(mempoolView({ mempool_enabled: true }, 'at_tip').copy, /will appear/);
  assert.match(mempoolView({ mempool_enabled: true }, 'syncing').copy, /historical/);
  assert.match(mempoolView({}, 'at_tip').copy, /unconfirmed/);
});

test('disabled index is not polled or reported as unavailable; missing intent still probes', async () => {
  let calls = 0;
  const client = { indexerStatus: async () => { calls++; return null; } };
  assert.deepEqual(await readIndexerCapability(client, { extra_index_enabled: false }), { disabled: true, index: null });
  assert.equal(calls, 0);
  assert.match(indexStatusCopy(true, true, null), /disabled by configuration/);
  await readIndexerCapability(client, {});
  assert.equal(calls, 1);
  assert.match(indexStatusCopy(false, true, null), /unavailable/);
  assert.match(indexStatusCopy(false, false, { status: 'caughtUp' }), /caught up/);
  assert.match(ENABLE_MINING, /enabled = true.*\[mining\]/);
  assert.doesNotMatch(ENABLE_MINING, /mining = true/);
});
