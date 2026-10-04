import { test } from 'node:test';
import assert from 'node:assert/strict';

globalThis.location = { search: '' };
const { summarizeRent, rentAccess, loadRentForecast, createRentSource } = await import('../js/storage-rent.js');
const height = 1_881_246;
const id = (n) => n.toString(16).padStart(64, '0');
const tip = { height, header_id: id(99) };
const indexer = { status: 'caughtUp', indexedHeight: height, fullHeight: height, repair: { pending: false, skipped: 0 } };
const context = { tip, indexer, identity: { extra_index_enabled: true }, reachable: true };
const box = (n, block, rent, tokens = []) => ({
  boxId: id(n), creationHeight: height + block - 1_051_200, rentOwed: rent,
  practicallyCollectable: true, assets: tokens.map((token) => ({ tokenId: id(token), amount: 100 })),
});
const page = (items, total = items.length) => ({ ok: true, status: 200, data: { items, total } });
const client = (read) => ({ storageRentMatures: read, tip: async () => ({ best_full_block: tip }), indexerStatus: async () => indexer });

test('rent totals use node estimates, include the next block once and deduplicate token IDs across the window', () => {
  const summary = summarizeRent([
    box(1, 1, 123_456_789, [10, 11]), box(2, 1, 1, [10]), box(3, 720, 20_000_000, [10, 12]),
    { ...box(4, 300, 0, [13]), practicallyCollectable: false },
  ], height);
  assert.deepEqual(summary.next, { rent: 123_456_790n, boxes: 2, tokens: 2 });
  assert.deepEqual(summary.window, { rent: 143_456_790n, boxes: 4, tokens: 4 });
  assert.equal(summary.excluded, 1);
  assert.equal(summary.fromHeight, height + 1);
  assert.equal(summary.toHeight, height + 720);
});

test('overdue, out-of-window, duplicate and incomplete rows cannot produce an apparent total', () => {
  for (const rows of [
    [box(1, 0, 1)], [box(1, 721, 1)], [box(1, 1, 1), box(1, 2, 2)],
    [{ ...box(1, 1, 1), assets: undefined }], [{ ...box(1, 1, 1), rentOwed: null }],
    [{ ...box(1, 1, 1), practicallyCollectable: false }],
  ]) assert.throws(() => summarizeRent(rows, height));
});

test('only a healthy current index allows the rent scan', () => {
  assert.equal(rentAccess(context), null);
  assert.equal(rentAccess({ ...context, reachable: false }), 'offline');
  assert.equal(rentAccess({ ...context, identity: { extra_index_enabled: false } }), 'disabled');
  assert.equal(rentAccess({ ...context, indexer: { ...indexer, status: 'syncing' } }), 'syncing');
  assert.equal(rentAccess({ ...context, indexer: { ...indexer, status: 'halted' } }), 'halted');
  assert.equal(rentAccess({ ...context, indexer: { ...indexer, repair: { skipped: 1 } } }), 'degraded');
  assert.equal(rentAccess({ ...context, indexer: { ...indexer, indexedHeight: height - 1 } }), 'unavailable');
});

test('all offset pages are summed and a complete empty response is a real zero', async () => {
  const rows = Array.from({ length: 1025 }, (_, n) => box(n, n % 720 + 1, 1, [10000]));
  const offsets = [];
  const result = await loadRentForecast(client(async (from, to, offset, limit) => {
    assert.equal(from, height + 1); assert.equal(to, height + 720);
    offsets.push(offset);
    return page(rows.slice(offset, offset + limit), rows.length);
  }), tip);
  assert.equal(result.state, 'ready');
  assert.equal(result.window.rent, 1025n);
  assert.equal(result.window.tokens, 1);
  assert.deepEqual(offsets, [0, 1024]);
  const empty = await loadRentForecast(client(async () => page([])), tip);
  assert.equal(empty.state, 'ready');
  assert.equal(empty.window.rent, 0n);
  assert.equal(empty.window.tokens, 0);
});

test('failed, truncated and oversized reads never display zero or partial totals', async () => {
  const unavailable = await loadRentForecast(client(async () => ({ ok: false, status: 503, reason: 'indexer-syncing' })), tip);
  assert.equal(unavailable.state, 'syncing');
  assert.equal('window' in unavailable, false);
  const truncated = await loadRentForecast(client(async () => page([], 3)), tip);
  assert.equal(truncated.state, 'changed');
  const large = await loadRentForecast(client(async () => page([], 20_000)), tip);
  assert.equal(large.state, 'large');
});

test('a reorg at the same height or newly incomplete index invalidates the computed totals', async () => {
  const api = client(async () => page([box(1, 1, 1)]));
  api.tip = async () => ({ best_full_block: { ...tip, header_id: id(100) } });
  assert.equal((await loadRentForecast(api, tip)).state, 'changed');
  api.tip = async () => ({ best_full_block: tip });
  api.indexerStatus = async () => ({ ...indexer, status: 'syncing' });
  assert.equal((await loadRentForecast(api, tip)).state, 'syncing');
});

test('success is cached per block identity and losing readiness invalidates an in-flight scan', async () => {
  let reads = 0;
  const api = client(async () => { reads++; return page([]); });
  const source = createRentSource(api);
  await source.refresh(context);
  await source.refresh(context);
  assert.equal(reads, 1);
  assert.equal(source.get().state, 'ready');
  let finish;
  api.storageRentMatures = () => new Promise((resolve) => { finish = resolve; });
  const pending = source.refresh({ ...context, tip: { ...tip, header_id: id(100) } });
  await source.refresh({ ...context, indexer: { ...indexer, status: 'syncing' } });
  finish(page([]));
  await pending;
  assert.equal(source.get().state, 'syncing');
});
