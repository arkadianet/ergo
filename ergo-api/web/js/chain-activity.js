import { num, bytes, dur, blockTime } from './format.js';
import { minerNode, poolLabel } from './miners.js';

const count = (n) => Number.isFinite(n) && n >= 0;
const timestamp = (n) => Number.isFinite(n) && n > 0;

// This is a bounded sample of applied blocks, not a network-wide rate. Only
// adjacent heights with usable header timestamps contribute to the interval.
export function summarizeBlocks(recent) {
  const seen = new Set();
  const blocks = (Array.isArray(recent) ? recent : []).filter((b) => {
    if (!Number.isInteger(b.height) || b.height < 0 || seen.has(b.height)) return false;
    seen.add(b.height);
    return true;
  }).sort((a, b) => b.height - a.height).slice(0, 10);
  const total = (field) => blocks.length && blocks.every((b) => count(b[field]))
    ? blocks.reduce((sum, b) => sum + b[field], 0) : null;
  const intervals = [];
  for (let i = 1; i < blocks.length; i++) {
    const newer = blocks[i - 1], older = blocks[i];
    if (newer.height - older.height !== 1 || !timestamp(newer.ts_unix_ms) || !timestamp(older.ts_unix_ms)) continue;
    const delta = newer.ts_unix_ms - older.ts_unix_ms;
    if (delta >= 0) intervals.push(delta / 1000);
  }
  const size = total('size_bytes');
  return {
    blocks,
    transactions: total('txs'),
    averageSize: size == null ? null : size / blocks.length,
    averageInterval: intervals.length ? intervals.reduce((a, b) => a + b, 0) / intervals.length : null,
    intervalCount: intervals.length,
  };
}

function element(tag, className, text) {
  const el = document.createElement(tag);
  if (className) el.className = className;
  if (text != null) el.textContent = text;
  return el;
}

function metric(label, value) {
  const cell = element('div');
  cell.append(element('dt', '', label), element('dd', '', value));
  return cell;
}

function blockLink(block, className, text) {
  const link = element(block.header_id ? 'a' : 'span', className, text);
  if (block.header_id) link.href = `#explorer/block/${block.header_id}`;
  return link;
}

export function recentChain(recent, { reachable } = {}) {
  const host = element('div', 'ov-chain');
  const sample = summarizeBlocks(recent);
  const { blocks } = sample;
  if (!blocks.length) {
    const empty = element('div', 'ov-chain-empty');
    empty.append(element('strong', '', recent == null ? 'Recent blocks unavailable' : 'Waiting for applied blocks'),
      element('p', '', recent == null ? 'The node has not returned a recent-block sample. Other node status may still be available.' : 'Block details and activity will appear as your node applies the chain.'));
    host.append(empty);
    return host;
  }

  const summary = element('dl', 'ov-chain-stats');
  summary.append(
    metric(`Transactions · ${blocks.length} blocks`, num(sample.transactions)),
    metric('Avg block interval', sample.averageInterval == null ? '—' : dur(Math.round(sample.averageInterval))),
    metric('Average block size', bytes(sample.averageSize)),
  );
  summary.children[1].title = `Mean header timestamp interval across ${sample.intervalCount} consecutive block pairs in this sample.`;
  host.append(summary);

  const figure = element('figure', 'ov-block-chart');
  const caption = element('figcaption', 'ov-block-chart__caption');
  caption.append(element('strong', '', 'Transactions per block'), element('span', '', reachable === false ? 'Last known sample' : 'Oldest → newest'));
  const plot = element('div', 'ov-block-chart__plot');
  const max = Math.max(1, ...blocks.map((b) => count(b.txs) ? b.txs : 0));
  const scale = element('div', 'ov-block-chart__scale');
  scale.setAttribute('aria-hidden', 'true');
  scale.append(element('span', '', num(max)), element('span', '', '0'));
  const bars = element('div', 'ov-block-chart__bars');
  bars.style.gridTemplateColumns = `repeat(${blocks.length}, minmax(0, 1fr))`;
  const readout = element('div', 'ov-block-chart__readout');
  const readBlock = (b) => {
    readout.replaceChildren(element('strong', '', `#${num(b.height)}`), element('span', '', `${num(b.txs)} tx · ${bytes(b.size_bytes)} · ${poolLabel(b.miner_address) || 'Miner not labeled'}`));
  };
  readBlock(blocks[0]);
  for (const b of [...blocks].reverse()) {
    const bar = blockLink(b, 'ov-block-bar');
    const label = `Block ${num(b.height)}: ${num(b.txs)} ${b.txs === 1 ? 'transaction' : 'transactions'}, ${bytes(b.size_bytes)}, mined ${blockTime(b.ts_unix_ms)}`;
    bar.setAttribute('aria-label', label);
    bar.title = label;
    bar.dataset.latest = String(b === blocks[0]);
    const ink = element('span', 'ov-block-bar__ink');
    ink.style.height = `${count(b.txs) ? b.txs / max * 100 : 0}%`;
    ink.setAttribute('aria-hidden', 'true');
    bar.append(ink);
    bar.addEventListener('mouseenter', () => readBlock(b));
    bar.addEventListener('focus', () => readBlock(b));
    bar.addEventListener('mouseleave', () => readBlock(blocks[0]));
    bar.addEventListener('blur', () => readBlock(blocks[0]));
    bars.append(bar);
  }
  plot.append(scale, bars);
  figure.append(caption, plot, readout);
  host.append(figure);

  const table = element('table', 'ov-block-table');
  table.setAttribute('aria-label', 'Five most recently applied blocks');
  const head = element('thead');
  const columns = element('tr');
  for (const name of ['Block', 'Mined', 'Tx', 'Size', 'Miner']) {
    const th = element('th', '', name);
    th.scope = 'col';
    columns.append(th);
  }
  head.append(columns);
  const body = element('tbody');
  for (const b of blocks.slice(0, 5)) {
    const row = element('tr');
    const height = element('th', 'ov-block-table__height');
    height.scope = 'row';
    height.append(blockLink(b, 'ex-link', num(b.height)));
    const mined = element('td', 'ov-block-table__mined');
    const time = element('time', '', blockTime(b.ts_unix_ms));
    if (timestamp(b.ts_unix_ms)) {
      time.dateTime = new Date(b.ts_unix_ms).toISOString();
      time.title = new Date(b.ts_unix_ms).toLocaleString();
    }
    mined.append(time);
    const txs = element('td', 'ov-block-table__number', num(b.txs));
    const size = element('td', 'ov-block-table__number', bytes(b.size_bytes));
    const miner = element('td', 'ov-block-table__miner');
    miner.append(minerNode(b.miner_address, b.miner_pk, { head: 4, tail: 4 }));
    [mined, txs, size, miner].forEach((cell, i) => { cell.dataset.label = ['Mined', 'Tx', 'Size', 'Miner'][i]; });
    row.append(height, mined, txs, size, miner);
    body.append(row);
  }
  table.append(head, body);
  host.append(table);
  return host;
}

export function eventDescription(event) {
  switch (event.kind) {
    case 'reorg': {
      const facts = [`New tip at ${num(event.height)}`];
      if (event.depth != null) facts.push(`${num(event.depth)} ${event.depth === 1 ? 'block' : 'blocks'} rolled back`);
      if (event.returnedTxsTotal != null) facts.push(`${num(event.returnedTxsTotal)} ${event.returnedTxsTotal === 1 ? 'transaction' : 'transactions'} returned to mempool`);
      return { title: 'Chain reorganized', detail: facts.join(' · '), tone: 'warn' };
    }
    case 'peerConnected': return { title: 'Peer connected', detail: event.addr || 'Address unavailable', tone: 'neutral' };
    case 'peerDisconnected': return { title: 'Peer disconnected', detail: event.addr || 'Address unavailable', tone: 'neutral' };
    case 'indexerStatus': return { title: 'Search index update', detail: event.detail || 'An index status change was recorded.', tone: 'neutral' };
    case 'syncWedged': return { title: 'Chain sync blocked', detail: event.detail || 'Review the node logs and recovery procedure.', tone: 'error' };
    case 'shadowDivergence': return { title: 'Validation divergence', detail: event.detail || 'Shadow validation differs from the reference node.', tone: 'error' };
    default: return { title: event.kind || 'Node event', detail: event.detail || '', tone: 'neutral' };
  }
}

export function nodeEvents(feed, { reachable } = {}) {
  const host = element('div', 'ov-node-events');
  const known = Array.isArray(feed?.events);
  const events = known ? feed.events.filter((e) => e.kind !== 'blockApplied').slice(-3).reverse() : [];
  if (!events.length) {
    const title = !known ? 'Event history unavailable' : reachable === false ? 'Last known event history' : 'No other events in the retained history';
    host.append(element('p', 'ov-node-events__quiet', title),
      element('p', 'ov-node-events__note', 'Peer changes, index updates and reorgs appear here. Applied blocks are shown above.'));
    return host;
  }
  for (const event of events) {
    const info = eventDescription(event);
    const row = element('div', 'ov-node-event');
    row.dataset.tone = info.tone;
    const title = element('strong', '', info.title);
    const time = element('time', '', blockTime(event.unixMs));
    if (timestamp(event.unixMs)) time.dateTime = new Date(event.unixMs).toISOString();
    row.append(title, time, element('p', '', info.detail));
    if (event.kind === 'reorg' && event.headerId) row.append(blockLink({ header_id: event.headerId }, 'ex-link', 'Inspect new tip ↗'));
    host.append(row);
  }
  const note = element('p', 'ov-node-events__note', `${reachable === false ? 'Last known data · ' : ''}Latest ${events.length} non-block events in retained history`);
  host.append(note);
  return host;
}
