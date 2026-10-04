import { test } from 'node:test';
import assert from 'node:assert/strict';

globalThis.location = { search: '' };
const { summarizeBlocks, eventDescription } = await import('../js/chain-activity.js');
const block = (height, ts = height * 120000) => ({ height, ts_unix_ms: ts, txs: 2, size_bytes: 1000 });

test('sample totals and intervals describe the applied blocks', () => {
  const sample = summarizeBlocks([block(12), block(10), block(11)]);
  assert.deepEqual(sample.blocks.map((b) => b.height), [12, 11, 10]);
  assert.equal(sample.transactions, 6);
  assert.equal(sample.averageSize, 1000);
  assert.equal(sample.averageInterval, 120);
  assert.equal(sample.intervalCount, 2);
});

test('missing data is not rendered as zero activity', () => {
  for (const recent of [null, []]) {
    const sample = summarizeBlocks(recent);
    assert.equal(sample.transactions, null);
    assert.equal(sample.averageSize, null);
    assert.equal(sample.averageInterval, null);
  }
  const sample = summarizeBlocks([{ ...block(10), txs: null, size_bytes: null }, block(9)]);
  assert.equal(sample.transactions, null);
  assert.equal(sample.averageSize, null);
  assert.equal(summarizeBlocks([{ ...block(10), txs: 0, size_bytes: 0 }]).transactions, 0);
});

test('gaps, duplicate heights and backwards timestamps do not invent intervals', () => {
  const sample = summarizeBlocks([block(15), block(15), block(13), block(12, 2000000), block(11, 0)]);
  assert.equal(sample.blocks.length, 4);
  assert.equal(sample.intervalCount, 0);
  assert.equal(sample.averageInterval, null);
  const tail = summarizeBlocks(Array.from({ length: 20 }, (_, i) => block(i + 1)));
  assert.equal(tail.blocks.length, 10);
  assert.equal(tail.blocks[0].height, 20);
});

test('reorg details retain their meaning and diagnostic events remain explicit', () => {
  const reorg = eventDescription({ kind: 'reorg', height: 123, depth: 2, returnedTxsTotal: 0 });
  assert.match(reorg.detail, /2 blocks rolled back/);
  assert.match(reorg.detail, /0 transactions returned/);
  assert.doesNotMatch(eventDescription({ kind: 'reorg', height: 123 }).detail, /rolled back/);
  assert.equal(eventDescription({ kind: 'syncWedged' }).tone, 'error');
  assert.equal(eventDescription({ kind: 'shadowDivergence' }).tone, 'error');
});
