// Header discovery has no trustworthy final height. Its ring is categorical;
// blocks and the optional index have measurable, independently named targets.
export function syncLayers({ status, sync, indexer, indexerHealth, identity, reachable }) {
  const percent = (value, target) => Number.isFinite(value) && value >= 0 && target > 0
    ? Math.max(0, Math.min(100, value / target * 100)) : null;
  const height = status?.best_full_block_height ?? sync?.best_full_block_height;
  const target = status?.best_header_height ?? sync?.best_header_height;
  const blocked = status?.sync_wedged || status?.apply_wedged || status?.last_storage_error || status?.last_block_apply_error || status?.shadow?.diverged;
  const blockPercent = percent(height, target);
  const indexPercent = percent(indexer?.indexedHeight, indexer?.fullHeight ?? height);
  const halted = indexer?.status === 'halted' || indexerHealth?.status === 'halted';
  const repair = indexerHealth?.repair?.pending || indexerHealth?.repair?.skipped > 0;
  const layers = [
    { id: 'headers', label: 'Headers', position: 'outer', percent: sync?.headers_chain_synced === true ? 100 : null,
      state: sync?.headers_chain_synced === true ? 'done' : sync?.headers_chain_synced === false ? 'discovering' : 'unknown' },
    { id: 'blocks', label: 'Blocks', position: 'middle', percent: blockPercent,
      state: blocked ? 'error' : status?.sync_state === 'stalled' || status?.sync_state === 'disconnected' ? 'paused' : status?.sync_state === 'at_tip' && !status?.bootstrap && blockPercent === 100 ? 'done' : blockPercent == null ? 'unknown' : 'progress' },
    { id: 'index', label: 'Search index', position: 'inner', percent: indexPercent,
      state: halted ? 'error' : repair ? 'repair' : identity?.extra_index_enabled === false ? 'disabled' : indexer?.status === 'caughtUp' && indexPercent === 100 ? 'done' : indexPercent == null ? 'unknown' : 'progress' },
  ];
  const names = { done: 'Ready', discovering: 'Discovering', unknown: 'Unavailable', error: 'Needs attention', repair: 'Repair needed', disabled: 'Disabled', paused: 'Paused', stale: 'Last known' };
  for (const layer of layers) {
    if (reachable === false) layer.state = 'stale';
    layer.text = names[layer.state] || `${(Math.floor(layer.percent * 100) / 100).toFixed(2)}%`;
  }
  return layers;
}
