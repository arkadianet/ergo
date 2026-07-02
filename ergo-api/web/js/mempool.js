// Mempool page: honest capacity (slots = Scala-parity, prominent; bytes =
// local budget, subordinate) + weight policy + revalidation, a log-axis
// smoothed fee-distribution curve, and the tx table with an in-node
// detail drawer (inputs/outputs/tokens) via the tx-detail endpoint.
import { api } from './api-client.js';
import { makeTable, copyBtn } from './table.js';
import { erg, num, bytes, ageMs, truncMiddle } from './format.js';
import { feeCurve } from './sparkline.js';
import { stats, logHistogram, logFrac } from './fee-stats.js';

let root = null;
let table = null;
const detailCache = {}; // tx_id -> ApiTxDetail | null

function span(text, color) {
  const s = document.createElement('span');
  s.textContent = text;
  if (color) s.style.color = color;
  return s;
}

function txidNode(t) {
  const w = document.createElement('span');
  // Links into the explorer's tx view — the ungated detail route resolves
  // unconfirmed txs too, so the link works for pool entries. Row expansion
  // still works: the drawer toggle only fires outside `.copy`/anchor targets.
  const a = document.createElement('a');
  a.className = 'ex-link';
  a.href = `#explorer/tx/${t.tx_id}`;
  a.textContent = t.tx_id;
  w.append(a, ' ', copyBtn(t.tx_id));
  return w;
}

function srcText(t) {
  const s = t.source || {};
  return s.kind === 'peer' ? `peer ${s.addr || ''}` : s.kind || 'local';
}
function srcNode(t) {
  const s = t.source || {};
  if (s.kind === 'peer') return span(`peer ${truncMiddle(s.addr || '', 6, 4)}`, 'var(--tx2)');
  return span(`local · ${s.kind || 'local'}`, 'var(--green)');
}

const COLS = [
  { key: 'tx_id', label: 'TX ID', render: txidNode, sort: (r) => r.tx_id },
  { key: 'fee', label: 'Fee ERG', width: 78, align: 'right', render: (r) => erg(r.fee_nano_erg), sort: (r) => r.fee_nano_erg },
  { key: 'feeb', label: 'Fee/B', width: 54, align: 'right', render: (r) => num(r.fee_per_byte_nano_erg), sort: (r) => r.fee_per_byte_nano_erg },
  { key: 'size', label: 'Size', width: 50, align: 'right', render: (r) => num(r.size_bytes), sort: (r) => r.size_bytes },
  { key: 'io', label: 'In/Out', width: 54, align: 'right', render: (r) => `${r.input_count}/${r.output_count}`, sort: (r) => r.input_count },
  { key: 'src', label: 'Source', width: 116, render: srcNode, sort: srcText },
  { key: 'age', label: 'Age', width: 46, align: 'right', render: (r) => ageMs(r.first_seen_age_ms), sort: (r) => r.first_seen_age_ms },
];

function ioRow(boxLike, withTokens) {
  const r = document.createElement('div');
  r.className = 'ov-kv';
  const a = document.createElement('span');
  a.textContent = boxLike.address ? truncMiddle(boxLike.address, 8, 6) : '(unresolved)';
  if (!boxLike.address) a.style.color = 'var(--tx3)';
  const v = document.createElement('span');
  v.textContent = erg(boxLike.value);
  r.append(a, v);
  const frag = document.createDocumentFragment();
  frag.append(r);
  if (withTokens && Array.isArray(boxLike.tokens)) {
    for (const tk of boxLike.tokens) {
      const tl = document.createElement('div');
      tl.className = 'mp-token';
      tl.textContent = `+ ${num(tk.amount)} ${truncMiddle(tk.token_id, 6, 4)}`;
      frag.append(tl);
    }
  }
  return frag;
}

function fillDetail(box, d) {
  box.replaceChildren();
  if (!d) {
    box.textContent = 'tx detail endpoint unavailable';
    box.style.color = 'var(--tx3)';
    return;
  }
  const grid = document.createElement('div');
  grid.className = 'drawer-grid';
  const col = (title, items, withTokens) => {
    const c = document.createElement('div');
    const h = document.createElement('div');
    h.className = 'micro-label';
    h.textContent = `${title} · ${items.length}`;
    c.append(h);
    for (const it of items) c.append(ioRow(it, withTokens));
    return c;
  };
  grid.append(col('Inputs', d.inputs || [], false), col('Outputs', d.outputs || [], true));
  box.append(grid);
}

function renderDetail(t) {
  const box = document.createElement('div');
  box.className = 'drawer-detail';
  if (t.tx_id in detailCache) {
    fillDetail(box, detailCache[t.tx_id]);
  } else {
    box.textContent = 'loading detail…';
    box.style.color = 'var(--tx3)';
    api.txDetail(t.tx_id).then((d) => {
      detailCache[t.tx_id] = d;
      if (box.isConnected) {
        box.style.color = '';
        fillDetail(box, d);
      }
    });
  }
  return box;
}

export function mount(el) {
  root = el;
  el.innerHTML = `
    <div class="pg-head">
      <div>
        <h1 class="pg-title">Mempool</h1>
        <span class="pg-count micro-label" data-count></span>
      </div>
    </div>
    <div class="mp-cap">
      <div class="mp-cell">
        <div class="micro-label">Slots · capacity (Scala parity)</div>
        <div class="mp-slot" data-slot>—</div>
        <div class="gauge" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0" aria-label="mempool slots used"><div class="gauge__fill" data-slotfill style="width:0%"></div></div>
      </div>
      <div class="mp-cell">
        <div class="micro-label">Bytes · local budget</div>
        <div class="mp-byte" data-byte>—</div>
        <div class="gauge gauge--sub" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0" aria-label="mempool bytes used"><div class="gauge__fill" data-bytefill style="width:0%"></div></div>
      </div>
      <div class="mp-cell">
        <div class="micro-label">Weight policy</div>
        <div data-weight>—</div>
      </div>
      <div class="mp-cell">
        <div class="micro-label">Revalidation</div>
        <div class="mp-reval" data-reval>—</div>
        <div class="micro-label">pending</div>
      </div>
    </div>
    <div class="mp-fee">
      <div class="mp-fee__row">
        <span class="micro-label">Fee/B dist · nERG (log)</span>
        <span class="micro-label" data-feestats></span>
      </div>
      <div class="mp-fee__curve" data-curve></div>
      <div class="mp-fee__axis"><span data-min></span><span data-max></span></div>
    </div>
    <div data-table></div>`;
  table = makeTable(el.querySelector('[data-table]'), COLS, {
    rowKey: (r) => r.tx_id,
    renderDetail,
    initialSort: { key: 'feeb', dir: -1 },
  });
}

function weightLabel(wf) {
  if (wf == null) return '—';
  if (typeof wf === 'string') return wf;
  return wf.kind || JSON.stringify(wf);
}

export async function onSlow() {
  const [summary, txWrap] = await Promise.all([api.mempoolSummary(), api.mempoolTransactions()]);
  const txs = (txWrap && txWrap.transactions) || [];
  const set = (sel, t) => {
    const e = root.querySelector(sel);
    if (e) e.textContent = t;
  };
  const setW = (sel, pct) => {
    const e = root.querySelector(sel);
    if (!e) return;
    const clamped = Math.min(100, Math.max(0, pct));
    e.style.width = `${clamped}%`;
    // Mirror the fill into the parent gauge's aria-valuenow for screen readers.
    if (e.parentElement) e.parentElement.setAttribute('aria-valuenow', String(Math.round(clamped)));
  };

  root.querySelector('[data-count]').textContent = `${num(summary?.size ?? txs.length)} unconfirmed`;

  if (summary) {
    const slotPct = summary.capacity_count > 0 ? (summary.size / summary.capacity_count) * 100 : 0;
    set('[data-slot]', `${num(summary.size)} / ${num(summary.capacity_count)}  ·  ${slotPct.toFixed(0)}%`);
    setW('[data-slotfill]', slotPct);
    const bytePct = summary.capacity_bytes > 0 ? (summary.total_bytes / summary.capacity_bytes) * 100 : 0;
    set('[data-byte]', `${bytes(summary.total_bytes)} / ${bytes(summary.capacity_bytes)}  ·  ${bytePct.toFixed(0)}%`);
    setW('[data-bytefill]', bytePct);
    set('[data-reval]', num(summary.revalidation_pending));
  }
  set('[data-weight]', weightLabel(txWrap && txWrap.weight_function));

  // fee distribution
  const feeb = txs.map((t) => Number(t.fee_per_byte_nano_erg)).filter((v) => Number.isFinite(v));
  const curveHost = root.querySelector('[data-curve]');
  curveHost.replaceChildren();
  if (feeb.length) {
    const st = stats(feeb);
    const { counts, lo, hi } = logHistogram(feeb, 28);
    curveHost.append(feeCurve(counts, { medianFrac: logFrac(st.median, lo, hi) }));
    set('[data-feestats]', `median ${num(st.median)} · mode ${num(st.mode)} · mean ${num(Math.round(st.mean))}`);
    set('[data-min]', `min ${num(lo)}`);
    set('[data-max]', `max ${num(hi)}`);
  } else {
    set('[data-feestats]', '');
    set('[data-min]', '');
    set('[data-max]', '');
  }

  table.update(txs);
}
