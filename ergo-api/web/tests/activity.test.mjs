import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ActivityBuffer, groupRecords, filterRecords, currentIssues, exportEvidence } from '../js/activity-model.js';

const record = (seq, overrides = {}) => ({ seq: String(seq), unixMs: 1000000 + Number(seq) % 100000, level: 'WARN', target: 'ergo_p2p::delivery', message: 'request timed out', fields: { peer: '127.0.0.1:9030', code: 'timeout' }, truncated: false, ...overrides });
const page = (records, overrides = {}) => ({ sessionId: 'a', nextSeq: records.at(-1)?.seq || '0', latestSeq: records.at(-1)?.seq || '0', oldestSeq: records[0]?.seq || '0', records, gap: false, reset: false, hasMore: false, droppedTotal: '0', retained: records.length, capacity: 2048, byteCapacity: 4194304, ...overrides });

test('paginated resume uses exact cursors and deduplicates overlapping polls', () => {
  const buffer = new ActivityBuffer();
  buffer.ingest(page([record('9007199254740993')], { latestSeq: '9007199254740994', hasMore: true }));
  assert.equal(buffer.cursor, '9007199254740993');
  buffer.ingest(page([record('9007199254740993'), record('9007199254740994')]));
  assert.equal(buffer.records.length, 2);
  buffer.ingest(page([record(1)]));
  assert.equal(buffer.cursor, '9007199254740994', 'late pages never rewind');
});

test('restart replaces prior session, gaps persist, clear removes all evidence', () => {
  const buffer = new ActivityBuffer();
  buffer.ingest(page([record(12)], { gap: true }));
  buffer.ingest(page([record(13)]));
  assert.equal(buffer.gap, true);
  buffer.ingest(page([record(1)], { sessionId: 'b', reset: true }));
  assert.deepEqual(buffer.records.map(r => r.seq), ['1']);
  assert.equal(buffer.restarted, true);
  assert.equal(buffer.gap, false);
  buffer.clear();
  assert.equal(buffer.records.length, 0);
  assert.equal(buffer.session, null);
});

test('invalid pages leave retained evidence and cursor intact', () => {
  const buffer = new ActivityBuffer(); buffer.ingest(page([record(1)]));
  for (const bad of [page([record('not-a-seq')]), page([record(2)], { nextSeq: '3', latestSeq: '2' }), page([record(2, { fields: null })])]) {
    assert.throws(() => buffer.ingest(bad));
    assert.equal(buffer.cursor, '1'); assert.equal(buffer.records.length, 1);
  }
});

test('browser retention is bounded independently of a slow server', () => {
  const buffer = new ActivityBuffer();
  for (let i = 0; i < 5; i++) buffer.ingest(page(Array.from({ length: 500 }, (_, j) => record(i * 500 + j + 1))));
  assert.equal(buffer.records.length, 2048);
  assert.equal(buffer.records[0].seq, '453');
  assert.equal(buffer.trimmed, true);
});

test('repeats share a five-minute group, retaining all original fields', () => {
  const a = record(1, { fields: { peer: 'a', latency_ms: 200, code: 'timeout' } });
  const b = record(2, { fields: { code: 'timeout', latency_ms: 400, peer: 'a' } });
  const groups = groupRecords([b, a]);
  assert.equal(groups.length, 1); assert.equal(groups[0].records.length, 2);
  assert.equal(groups[0].records[1].fields.latency_ms, 400);
  const outside = record(3, { ...b, seq: '3', unixMs: a.unixMs + 300001 });
  assert.equal(groupRecords([a, b, outside]).length, 2);
});

test('different peers, block IDs, reasons, severities and truncated records stay separate', () => {
  const variants = [record(1), record(2, { fields: { peer: 'other' } }), record(3, { fields: { block: 'a' } }), record(4, { fields: { block: 'b' } }), record(5, { fields: { reason: 'unrelated failure' } }), record(6, { level: 'ERROR' }), record(7, { truncated: true }), record(8, { unixMs: 1 })];
  assert.equal(groupRecords(variants).length, variants.length);
});

test('lifecycle records are explicit and never collapsed across recovery', () => {
  const lifecycle = (seq, state) => record(seq, { level: state === 'active' ? 'WARN' : 'INFO', message: 'Network condition changed', fields: { code: 'node_condition', condition: 'network', state } });
  const groups = groupRecords([lifecycle(1, 'active'), lifecycle(2, 'recovered'), lifecycle(3, 'active')]);
  assert.deepEqual(groups.map(g => g.state), ['active', 'recovered', 'active']);
  assert.equal(groupRecords([record(1, { level: 'ERROR' })])[0].state, 'recorded');
});

test('filters operate on occurrences before aggregation and preserve hidden raw records', () => {
  const records = [record(1), record(2, { unixMs: 600000 }), record(3, { level: 'INFO', message: 'heartbeat tick' }), record(4, { level: 'ERROR', target: 'ergo_state', fields: { block: 'ABC123' } })];
  assert.equal(filterRecords(records, {}).length, 3);
  assert.equal(filterRecords(records, { routine: true }).length, 4);
  const recovery = record(5, { level: 'INFO', fields: { code: 'node_condition', condition: 'network', state: 'recovered' } });
  assert.deepEqual(filterRecords([...records, recovery], { level: 'highlights' }).map(r => r.seq), ['1', '2', '4', '5']);
  assert.deepEqual(filterRecords(records, { query: 'abc123', subsystem: 'Storage', level: 'ERROR' }).map(r => r.seq), ['4']);
  assert.deepEqual(filterRecords(records, { minutes: 1 }, 1000100).map(r => r.seq), ['1', '4']);
  assert.equal(records.length, 4);
});

test('current faults are independent of historical error logs; recovery needs applied progress', () => {
  assert.deepEqual(currentIssues(null, { status: 'halted' }).map(i => i.id), ['index']);
  const status = { peer_count: 5, sync_state: 'syncing', best_full_block_height: 100, best_header_height: 999, last_block_apply_error: { height: 100, reason: 'bad proof' } };
  assert.ok(currentIssues(status).some(i => i.id === 'rejection'));
  status.best_full_block_height = 101;
  assert.equal(currentIssues(status).length, 0);
  status.last_storage_error = 'disk write failed';
  assert.deepEqual(currentIssues(status, { status: 'halted' }).map(i => i.id), ['storage', 'index']);
  status.last_block_apply_error.height = 0;
  assert.ok(currentIssues(status).some(i => i.id === 'rejection'));
});

test('evidence export round-trips hostile messages and includes scope metadata', () => {
  const records = [record(1, { message: '<img src=x onerror=alert(1)>\nnew line' })];
  const lines = exportEvidence(records, { sessionId: 'session', gap: true }).trim().split('\n').map(JSON.parse);
  assert.equal(lines.length, 2);
  assert.equal(lines[0].recordCount, 1); assert.equal(lines[0].gap, true);
  assert.equal(lines[1].message, records[0].message);
});
