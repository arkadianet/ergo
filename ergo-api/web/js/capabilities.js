// `[mempool]` has no `enabled` key (unknown keys fail config load), and the
// node also forces the mempool off without UTXO state.
const MEMPOOL_DISABLED = 'This node does not admit or retain pending transactions. Set disabled = false in the [mempool] configuration table and start without --mempool-disabled to use this view. Nodes with state_type = "digest" or verify_transactions = false in [node] keep the mempool off.';

// Missing capability fields on older nodes mean unknown, not disabled.
export function mempoolView(identity, syncState) {
  if (identity?.mempool_enabled === false) return { disabled: true, title: 'Mempool disabled', copy: MEMPOOL_DISABLED };
  if (identity?.mempool_enabled !== true) return { disabled: false, title: 'No pending transactions returned', copy: 'Mempool configuration is unconfirmed. These values do not establish that transaction admission is enabled.' };
  return { disabled: false, title: 'No pending transactions', copy: syncState === 'syncing' ? 'Your node is still syncing historical blocks. An empty local mempool does not mean the network has no transactions.' : "Your node's mempool is empty. New transactions will appear here as they arrive." };
}

export async function readIndexerCapability(client, identity) {
  if (identity?.extra_index_enabled === false) return { disabled: true, index: null };
  return { disabled: false, index: await client.indexerStatus() };
}

export function indexStatusCopy(disabled, stale, indexer) {
  if (disabled) return 'Search index disabled by configuration.';
  return stale ? 'Search index status unavailable. Any retained index condition is last reported, not confirmed current.' : `Search index: ${indexer.status === 'caughtUp' ? 'caught up' : indexer.status || 'unknown'}.`;
}

export const ENABLE_MINING = 'This node does not serve mining work. Set enabled = true in the [mining] configuration table to hand out candidates to external miners.';
