// Status interpretation is separate from presentation so degraded and unknown
// states can be checked without a live node. No claim of overall health follows
// merely from API connectivity or a completed block-sync percentage.
export function blockRejectionState(status) {
  const error = status?.last_block_apply_error;
  if (!error) return 'none';
  const applied = status.best_full_block_height;
  // Match the health probe: only committed blocks beyond the rejected height
  // establish progress. Age, header height and an at-tip label alone do not.
  return Number.isSafeInteger(error.height) && error.height > 0 &&
    Number.isSafeInteger(applied) && applied > error.height ? 'historical' : 'unresolved';
}

export function hasActiveNodeIssue(status) {
  return !!(status?.sync_wedged || status?.apply_wedged || status?.last_storage_error ||
    blockRejectionState(status) === 'unresolved' || status?.shadow?.diverged);
}

export function nodeGuidance({ reachable, status, indexer, indexerHealth, identity }) {
  const result = (tone, title, detail, action, destination) => ({ tone, title, detail, action, destination });
  if (reachable === false) return result('warn', 'Reconnect to your node', 'These values are from the last response. Check that the node is running and that its API is reachable. This page retries automatically.', null, null);
  if (!status) return result('neutral', 'Getting a live picture', 'Waiting for the first status response. No health assessment is available yet.', null, null);
  if (hasActiveNodeIssue(status)) return result('error', 'Review reported issues', 'The node has reported a processing, storage or validation issue. Check the diagnostic message and node logs before taking recovery action.', 'Review diagnostics', 'diagnostics');
  if (status.peer_count === 0 || status.sync_state === 'disconnected') return result('warn', 'Restore network connectivity', 'The API is responding, but the node has no peer connections. Inspect the peer list and your network configuration.', 'Inspect peers', 'peers');
  if (status.sync_state === 'stalled') return result('warn', 'Investigate the sync stall', 'The node reports that sync has stopped progressing. Start with peer connectivity, then check the node logs.', 'Inspect peers', 'peers');
  if (indexer?.status === 'halted' || indexerHealth?.status === 'halted') return result('error', 'Search indexing is halted', 'Address, box and token lookups may be unavailable. Review the index diagnostics; block sync and indexing are separate processes.', 'Review index diagnostics', 'diagnostics');
  if (identity?.verify_transactions === false) return result('warn', 'Transaction verification is disabled', 'This node is configured without transaction verification. A completed sync does not establish that it has fully validated the chain. Review the node configuration.', null, null);
  if (status.bootstrap?.popow_phase === 'abandoned') return result('neutral', 'Ordinary header sync is continuing', 'The NiPoPoW bootstrap attempt was abandoned. Review the reported reason in the sync summary while ordinary header sync continues.', null, null);
  if (status.bootstrap) return result('neutral', 'Bootstrap is still running', 'The node is preparing chain state. Full sync and search availability will be assessed as their status becomes available.', null, null);
  if (status.sync_state === 'syncing') return result('neutral', 'Let initial sync progress', 'The node is applying historical blocks. Local chain data is incomplete, and address or token searches may still be unavailable.', 'Browse local blocks', 'explorer');
  if (indexerHealth?.repair?.pending) return result('warn', 'Search index repair is running', 'The node reports a pending index repair. Some lookups may be incomplete until it finishes.', 'Review index diagnostics', 'diagnostics');
  if (indexerHealth?.repair?.skipped > 0) return result('warn', 'Some index entries were skipped', 'Index repair completed with skipped boxes. Search results may be incomplete; review the index diagnostics.', 'Review index diagnostics', 'diagnostics');
  if (identity?.extra_index_enabled === false) return result('neutral', 'Search index is disabled', 'Blocks remain browsable. Address, box and token lookups require the optional extra index.', 'Browse local blocks', 'explorer');
  if (indexer?.status === 'syncing') return result('neutral', 'Chain search is catching up', 'Block sync and search indexing are separate. Browse applied blocks now; address, box and token lookups depend on the index catching up.', 'Browse local blocks', 'explorer');
  if (!indexer || indexer.status !== 'caughtUp') return result('neutral', 'Search availability is unconfirmed', 'The node has not returned a current ready status for its search index. You can still try browsing local blocks.', 'Open explorer', 'explorer');
  if (status.sync_state === 'at_tip') return result('ok', 'Ready to explore', 'The node reports it is at the chain tip and the search index is caught up. Browse blocks, transactions and indexed assets.', 'Open explorer', 'explorer');
  return result('neutral', 'Check chain progress', 'The node returned an unrecognized sync state. Review the available diagnostics before assuming it is ready.', 'Review diagnostics', 'diagnostics');
}
