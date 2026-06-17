// Peers page: composition strip (direction / state / agents) + the shared
// sortable card-row table with a per-peer detail drawer. In/Out show each
// peer's post-handshake framed bytes (plumbed through ergo-p2p).
import { api } from './api-client.js';
import { makeTable, copyBtn } from './table.js';
import { num, dur, bytes } from './format.js';

let root = null;
let table = null;
let ourHeight = null;

const dirColor = (d) => (d === 'outbound' ? 'var(--blue)' : 'var(--purple)');
const stateColor = (s) =>
  s === 'connected' ? 'var(--green)' : s === 'handshaking' ? 'var(--yellow)' : 'var(--tx3)';

function span(text, color) {
  const s = document.createElement('span');
  s.textContent = text;
  if (color) s.style.color = color;
  return s;
}

function dirNode(p) {
  return span(p.direction === 'outbound' ? 'out' : 'in', dirColor(p.direction));
}
function stateNode(p) {
  const w = document.createElement('span');
  const dot = span('● ', stateColor(p.state));
  w.append(dot, document.createTextNode(p.state || '—'));
  return w;
}
function heightNode(p) {
  if (p.peer_height == null) return span('—', 'var(--tx3)');
  if (ourHeight != null && p.peer_height < ourHeight) {
    return span(`${num(p.peer_height)} · −${num(ourHeight - p.peer_height)}`, 'var(--yellow)');
  }
  return span(num(p.peer_height), 'var(--green)');
}

const COLS = [
  { key: 'addr', label: 'Address', width: 150, sort: (r) => r.addr },
  { key: 'dir', label: 'Dir', width: 40, render: dirNode, sort: (r) => r.direction },
  { key: 'state', label: 'State', width: 78, render: stateNode, sort: (r) => r.state },
  { key: 'height', label: 'Height', width: 84, align: 'right', render: heightNode, sort: (r) => r.peer_height ?? -1 },
  { key: 'in', label: 'In', width: 58, align: 'right', render: (r) => bytes(r.bytes_in), sort: (r) => r.bytes_in ?? -1 },
  { key: 'out', label: 'Out', width: 58, align: 'right', render: (r) => bytes(r.bytes_out), sort: (r) => r.bytes_out ?? -1 },
  { key: 'score', label: 'Score', width: 48, align: 'right', sort: (r) => r.score },
  { key: 'agent', label: 'Agent', sort: (r) => r.agent || '' },
  { key: 'conn', label: 'Conn', width: 56, align: 'right', render: (r) => dur(r.connected_seconds), sort: (r) => r.connected_seconds },
];

function kv(label, value) {
  const r = document.createElement('div');
  r.className = 'ov-kv';
  const l = document.createElement('span');
  l.textContent = label;
  const v = document.createElement('span');
  if (value instanceof Node) v.append(value);
  else v.textContent = value;
  r.append(l, v);
  return r;
}

function renderDetail(p) {
  const grid = document.createElement('div');
  grid.className = 'drawer-grid';

  const left = document.createElement('div');
  const lh = document.createElement('div');
  lh.className = 'micro-label';
  lh.textContent = 'Connection';
  left.append(
    lh,
    kv('direction', span(p.direction, dirColor(p.direction))),
    kv('state', span(p.state, stateColor(p.state))),
    kv('connected for', dur(p.connected_seconds)),
    kv('last seen', `${dur(p.last_seen_seconds)} ago`),
    kv('score', String(p.score)),
  );

  const right = document.createElement('div');
  const rh = document.createElement('div');
  rh.className = 'micro-label';
  rh.textContent = 'Peer';
  const agentVal = document.createElement('span');
  agentVal.append(document.createTextNode(p.agent || '—'));
  if (p.agent) agentVal.append(' ', copyBtn(p.agent));
  right.append(
    rh,
    kv('height', heightNode(p)),
    kv('agent', agentVal),
    kv('protocol', p.sync_version || '—'),
    kv('bytes in / out', `${bytes(p.bytes_in)} / ${bytes(p.bytes_out)}`),
    kv('node name', p.node_name || '—'),
  );

  grid.append(left, right);
  return grid;
}

export function mount(el) {
  root = el;
  el.innerHTML = `
    <div class="pg-head">
      <div>
        <h1 class="pg-title">Peers</h1>
        <span class="pg-count micro-label" data-count></span>
      </div>
    </div>
    <div class="comp" data-comp></div>
    <div data-table></div>`;
  table = makeTable(el.querySelector('[data-table]'), COLS, {
    rowKey: (r) => r.addr,
    renderDetail,
    initialSort: { key: 'conn', dir: -1 },
  });
}

function bar(segments) {
  const w = document.createElement('div');
  w.className = 'distbar';
  for (const s of segments) {
    const d = document.createElement('div');
    d.style.width = `${Math.max(0, s.frac * 100)}%`;
    d.style.background = s.color;
    w.append(d);
  }
  return w;
}

function compCell(title, body) {
  const c = document.createElement('div');
  c.className = 'comp__cell';
  const h = document.createElement('div');
  h.className = 'micro-label';
  h.textContent = title;
  c.append(h, body);
  return c;
}

function renderComp(peers) {
  const host = root.querySelector('[data-comp]');
  host.replaceChildren();
  const total = peers.length || 1;
  const out = peers.filter((p) => p.direction === 'outbound').length;
  const inn = peers.filter((p) => p.direction === 'inbound').length;
  const conn = peers.filter((p) => p.state === 'connected').length;
  const hs = peers.filter((p) => p.state === 'handshaking').length;
  const other = peers.length - conn - hs;

  // direction
  const dirBody = document.createElement('div');
  dirBody.append(
    bar([
      { frac: out / total, color: 'var(--blue)' },
      { frac: inn / total, color: 'var(--purple)' },
    ]),
  );
  const dl = document.createElement('div');
  dl.className = 'comp__legend';
  dl.textContent = `out ${out} · in ${inn}`;
  dirBody.append(dl);

  // state
  const stBody = document.createElement('div');
  stBody.append(
    bar([
      { frac: conn / total, color: 'var(--green)' },
      { frac: hs / total, color: 'var(--yellow)' },
      { frac: other / total, color: 'var(--tx3)' },
    ]),
  );
  const sl = document.createElement('div');
  sl.className = 'comp__legend';
  sl.textContent = `connected ${conn} · handshaking ${hs}${other ? ` · other ${other}` : ''}`;
  stBody.append(sl);

  // agents
  const counts = {};
  for (const p of peers) {
    const a = (p.agent || 'unknown').split('/').slice(0, 2).join('/');
    counts[a] = (counts[a] || 0) + 1;
  }
  const agBody = document.createElement('div');
  agBody.className = 'comp__agents';
  Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 3)
    .forEach(([a, n]) => {
      const r = document.createElement('div');
      r.className = 'ov-kv';
      const l = document.createElement('span');
      l.textContent = a;
      const v = document.createElement('span');
      v.textContent = String(n);
      r.append(l, v);
      agBody.append(r);
    });

  host.append(compCell('Direction', dirBody), compCell('State', stBody), compCell('Agents', agBody));
}

export async function onSlow() {
  const [peers, status] = await Promise.all([api.peers(), api.status()]);
  if (status) ourHeight = status.best_header_height ?? null;
  const list = Array.isArray(peers) ? peers : [];
  root.querySelector('[data-count]').textContent = `${list.length} connected`;
  renderComp(list);
  table.update(list);
}
