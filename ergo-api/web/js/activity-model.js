// Pure interpretation of operator evidence. Log severity describes an occurrence,
// not a current health verdict. Only status/coded lifecycle evidence establishes
// recovery; neither silence nor a reconnect can do so.
import { blockRejectionState } from './node-guidance.js';

export const BUFFER_CAP = 2048;
const BYTE_CAP = 4 * 1024 * 1024;
const GROUP_WINDOW_MS = 5 * 60 * 1000;
const decimal = (v) => typeof v === 'string' && /^\d{1,20}$/.test(v) && BigInt(v) <= 18446744073709551615n;
const compare = (a, b) => BigInt(a.seq) < BigInt(b.seq) ? -1 : BigInt(a.seq) > BigInt(b.seq) ? 1 : 0;

export class ActivityBuffer {
  constructor() { this.clear(); }
  clear() {
    this.session = null; this.cursor = '0'; this.records = []; this.meta = null;
    this.gap = false; this.restarted = false; this.trimmed = false;
  }
  ingest(page) {
    if (!page || typeof page.sessionId !== 'string' || !page.sessionId ||
      !decimal(page.nextSeq) || !decimal(page.latestSeq) || !decimal(page.oldestSeq) || !decimal(page.droppedTotal) ||
      !Array.isArray(page.records) || page.records.length > 500 ||
      BigInt(page.nextSeq) > BigInt(page.latestSeq) ||
      page.records.some(r => !r || !decimal(r.seq) || typeof r.message !== 'string' || typeof r.target !== 'string' ||
        !['INFO', 'WARN', 'ERROR'].includes(r.level) || !Number.isSafeInteger(r.unixMs) || r.unixMs < 0 || r.unixMs > 8640000000000000 ||
        !r.fields || typeof r.fields !== 'object' || Array.isArray(r.fields) || BigInt(r.seq) > BigInt(page.nextSeq))) {
      throw new Error('The node returned an invalid activity page. Retained evidence has not been replaced.');
    }
    const changed = this.session && this.session !== page.sessionId;
    if (changed || page.reset) {
      this.records = []; this.cursor = '0'; this.gap = false; this.trimmed = false;
      this.restarted = true;
    }
    // A late/replayed page must never wind the cursor backwards.
    if (!changed && !page.reset && BigInt(page.nextSeq) < BigInt(this.cursor)) return 0;
    this.session = page.sessionId;
    const seen = new Set(this.records.map(r => r.seq));
    const fresh = page.records.filter(r => !seen.has(r.seq) && seen.add(r.seq));
    this.records = [...this.records, ...fresh].sort(compare);
    this.gap ||= !!page.gap;
    this.cursor = page.nextSeq;
    this.meta = { ...page, records: undefined };
    // Bound browser memory independently of server retention and pagination.
    let bytes = 0;
    let start = this.records.length;
    for (; start > 0; start--) {
      const size = new TextEncoder().encode(JSON.stringify(this.records[start - 1])).length;
      if (bytes + size > BYTE_CAP || this.records.length - start >= BUFFER_CAP) break;
      bytes += size;
    }
    if (start > 0) { this.trimmed = true; this.records = this.records.slice(start); }
    return fresh.length;
  }
}

const subsystems = [
  ['wallet', 'Wallet'], ['mining', 'Mining'], ['indexer', 'Index'], ['p2p', 'Network'],
  ['mempool', 'Mempool'], ['sync', 'Sync'], ['state', 'Storage'], ['api', 'API'], ['sigma', 'Validation'], ['validation', 'Validation'],
];
export function describeRecord(record) {
  const fields = record.fields || {};
  const code = String(fields.code || fields.event || '');
  const condition = fields.code === 'node_condition' ? fields.condition : null;
  const state = condition && ['active', 'recovered'].includes(fields.state) ? fields.state : 'recorded';
  const subsystem = condition === 'network' ? 'Network' : condition === 'sync' ? 'Sync' : condition === 'block_rejection' ? 'Validation'
    : subsystems.find(([term]) => record.target.toLowerCase().includes(term))?.[1] || 'Node';
  let title = record.message || code.replaceAll('_', ' ') || 'Node event';
  if (code.startsWith('storage_error')) title = 'Storage operation failed';
  else if (code === 'ad_proofs_mismatch') title = 'Block proof did not match';
  title = title.charAt(0).toUpperCase() + title.slice(1);
  const routine = record.level === 'INFO' && ['heartbeat tick', 'node_gauges', 'chain progress'].includes(record.message);
  return { title, subsystem, code, state, routine, level: record.level };
}

// Preserve identity and reason exactly. Only timing/counter mechanics are
// ignored in the grouping key; their original values remain in every record.
const volatile = new Set(['age_ms', 'elapsed_ms', 'duration_ms', 'latency_ms', 'attempt', 'retry_count', 'rel_ms']);
function fingerprint(record) {
  const fields = Object.entries(record.fields).filter(([k]) => !volatile.has(k)).sort(([a], [b]) => a.localeCompare(b));
  return JSON.stringify([record.target, record.level, record.message, fields]);
}

export function groupRecords(records) {
  const groups = [], latest = new Map();
  for (const record of [...records].sort(compare)) {
    const description = describeRecord(record);
    const key = fingerprint(record);
    let group = latest.get(key);
    // Never merge across a backwards wall clock or a lifecycle transition.
    if (!group || description.state !== 'recorded' || record.truncated || group.truncated ||
      record.unixMs < group.last || record.unixMs - group.first > GROUP_WINDOW_MS) {
      group = { ...description, id: record.seq, first: record.unixMs, last: record.unixMs, lastSeq: record.seq, records: [], truncated: !!record.truncated };
      groups.push(group); latest.set(key, group);
    }
    group.records.push(record); group.last = record.unixMs; group.lastSeq = record.seq;
  }
  return groups.sort((a, b) => BigInt(a.lastSeq) > BigInt(b.lastSeq) ? -1 : 1);
}

export function filterRecords(records, filters, now = Date.now()) {
  const query = (filters.query || '').trim().toLowerCase();
  const minutes = Number(filters.minutes) || 0;
  return records.filter(record => {
    const d = describeRecord(record);
    return (!filters.level || (filters.level === 'highlights' ? record.level !== 'INFO' || d.state === 'recovered' : filters.level === 'attention' ? record.level !== 'INFO' : record.level === filters.level)) &&
      (!filters.subsystem || d.subsystem === filters.subsystem) &&
      (filters.routine || !d.routine) &&
      (!minutes || record.unixMs >= now - minutes * 60000) &&
      (!query || `${d.title} ${d.code} ${record.target} ${JSON.stringify(record.fields)}`.toLowerCase().includes(query));
  });
}

export function currentIssues(status, indexer) {
  status ||= {};
  const issues = [];
  const add = (id, title, detail, action, severity = 'error') => issues.push({ id, title, detail, action, severity });
  if (status.last_storage_error) add('storage', 'Storage needs attention', status.last_storage_error, 'Inspect disk space, permissions and the storage error before restarting. Preserve the file logs.');
  if (status.sync_wedged) add('fork', 'Chain sync is blocked', `The chain forks below the rollback window${status.sync_wedged.fork_below_height != null ? ` at height ${status.sync_wedged.fork_below_height}` : ''}.`, 'Review the deep-fork recovery procedure and node logs before resyncing.');
  if (status.apply_wedged) add('apply', 'Block processing is taking too long', 'The live processing threshold has been exceeded.', 'Inspect processing and storage evidence; a responsive API does not establish chain progress.');
  if (status.shadow?.diverged) add('shadow', 'Reference validation diverged', `${status.shadow.diverged.kind || 'Divergence'} at height ${status.shadow.diverged.height ?? 'unknown'}.`, 'Compare the full block IDs and reference-node evidence.');
  if (blockRejectionState(status) === 'unresolved') add('rejection', 'Block rejection needs review', status.last_block_apply_error.reason || 'The applied chain has not advanced beyond the rejected height.', 'Inspect the rejected block and its reason. Recovery requires applied blocks beyond the rejected height.');
  if (status.peer_count === 0 || status.sync_state === 'disconnected') add('network', 'No peer connections', 'The node cannot follow the network without connected peers.', 'Check the Peers page, network connectivity and configured peer addresses.', 'warn');
  if (status.sync_state === 'stalled') add('sync', 'Chain sync has stalled', 'The node is reporting no recent chain progress.', 'Check peer connectivity and block-processing warnings.', 'warn');
  if (indexer?.status === 'halted') add('index', 'Search indexing is halted', indexer.haltReason || 'Chain search may be incomplete.', 'Inspect index errors and repair state. Block sync and indexing recover separately.');
  if (indexer?.repair?.pending) add('repair', 'Search index repair is running', 'Indexed results may be incomplete while repair is pending.', 'Watch index progress and retain any repair errors.', 'warn');
  if (indexer?.repair?.skipped > 0) add('skipped', 'Index repair skipped entries', `${indexer.repair.skipped} boxes were skipped.`, 'Inspect index diagnostics before relying on complete search results.', 'warn');
  return issues;
}

export function exportEvidence(records, metadata) {
  return [JSON.stringify({ type: 'activity-export', version: 1, ...metadata, recordCount: records.length }),
    ...records.map(record => JSON.stringify({ type: 'log', ...record }))].join('\n') + '\n';
}
