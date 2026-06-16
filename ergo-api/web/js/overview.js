// Overview cockpit: a no-scroll KPI band over a 2x2 quadrant + system
// strip, with a Cockpit/Charts toggle. KPI band updates at 1 Hz from the
// cheap status/info; the quadrant + sysbar rebuild on the 4 s slow tick.
import { api } from './api-client.js';
import { sparkline } from './sparkline.js';
import { num, bytes, dur } from './format.js';
import { subscribe, promptAuthorize } from './auth.js';

const HISTORY_LEN = 60;
const hist = { blockTimes: [], mempool: [], height: [], difficulty: [] };
const state = {
  status: null,
  info: null,
  tip: null,
  identity: null,
  peerDist: null,
  lastBlockMs: null,
  lastHeight: null,
};
let root = null;
let viewMode = localStorage.getItem('ergo.ovview') || 'cockpit';

// ---- domain formatters ----
function parseDiff(s) {
  const n = Number(s);
  return Number.isFinite(n) && n > 0 ? n : null;
}
function fmtSI(d, units) {
  if (d == null || !Number.isFinite(d) || d <= 0) return '—';
  let i = 0;
  let v = d;
  while (v >= 1000 && i < units.length - 1) {
    v /= 1000;
    i++;
  }
  return v.toFixed(2) + units[i];
}
const fmtDiff = (d) => fmtSI(d, ['', 'K', 'M', 'G', 'T', 'P', 'E', 'Z', 'Y']);
const fmtHr = (h) => fmtSI(h, ['H/s', 'KH/s', 'MH/s', 'GH/s', 'TH/s', 'PH/s', 'EH/s']);
function deriveHr(diff, info) {
  const s = Math.max(1, (info?.target_block_interval_ms ?? 120000) / 1000);
  return diff / s;
}
function push(buf, v) {
  if (v == null) return;
  buf.push(Number(v));
  if (buf.length > HISTORY_LEN) buf.shift();
}

const KPI = [
  ['height', 'HEIGHT'],
  ['lastblk', 'LAST BLOCK'],
  ['diff', 'DIFFICULTY'],
  ['hr', 'HASHRATE est'],
  ['peers', 'PEERS'],
  ['mp', 'MEMPOOL'],
  ['up', 'UPTIME'],
];

function setText(sel, t) {
  const e = root && root.querySelector(sel);
  if (e) e.textContent = t;
}

export function mount(el) {
  root = el;
  el.innerHTML = `
    <div class="ov-prompt banner banner--info" data-auth-prompt hidden></div>
    <div class="ov-top">
      <div class="ov-ident" data-ident hidden>
        <span class="ov-ident__mode" data-ident-mode>—</span>
        <span class="ov-ident__chips" data-ident-chips></span>
      </div>
      <div class="tabs ov-toggle">
        <button class="tab" type="button" data-view="cockpit">Cockpit</button>
        <button class="tab" type="button" data-view="charts">Charts</button>
      </div>
    </div>
    <div class="kpi">
      ${KPI.map(
        ([k, l]) =>
          `<div class="kpi__t"><div class="micro-label">${l}</div>` +
          `<div class="kpi__v" data-k="${k}">—</div>` +
          `<div class="kpi__s" data-s="${k}"></div></div>`,
      ).join('')}
    </div>
    <div class="ov-body"></div>`;
  el.querySelectorAll('.ov-toggle .tab').forEach((b) => {
    b.setAttribute('aria-selected', String(b.dataset.view === viewMode));
    b.onclick = () => {
      viewMode = b.dataset.view;
      localStorage.setItem('ergo.ovview', viewMode);
      el.querySelectorAll('.ov-toggle .tab').forEach((x) =>
        x.setAttribute('aria-selected', String(x.dataset.view === viewMode)),
      );
      renderBody();
    };
  });
  // Authorize prompt: visible only while no api_key is set. Built once; the
  // subscription just toggles visibility as the auth state changes.
  const prompt = root.querySelector('[data-auth-prompt]');
  if (prompt) {
    const txt = document.createElement('span');
    txt.textContent = 'Authorize to unlock operator controls (voting, wallet).';
    const btn = document.createElement('button');
    btn.className = 'btn btn--primary btn--sm';
    btn.type = 'button';
    btn.textContent = 'Authorize';
    btn.addEventListener('click', promptAuthorize);
    prompt.append(txt, btn);
    subscribe((s) => {
      prompt.hidden = s !== 'none';
    });
  }
  renderBody();
  if (state.status) onFast({ status: state.status, info: state.info });
  // Node identity is static config — fetch once on mount. Render from
  // the cached copy first so a re-entry doesn't flash empty.
  if (state.identity) renderIdentity();
  else fetchIdentity();
}

// ---- node identity strip (static, fetched once on mount) ----
async function fetchIdentity() {
  const id = await api.identity();
  if (id) state.identity = id;
  renderIdentity();
}

function chip(label, on) {
  const c = document.createElement('span');
  c.className = `pill ${on ? 'pill--ok' : ''}`;
  c.textContent = `${label} ${on ? 'on' : 'off'}`;
  return c;
}

function renderIdentity() {
  if (!root) return;
  const wrap = root.querySelector('[data-ident]');
  const modeEl = root.querySelector('[data-ident-mode]');
  const chips = root.querySelector('[data-ident-chips]');
  if (!wrap || !modeEl || !chips) return;
  const id = state.identity;
  // No identity yet (fetch failed / in flight): keep the strip hidden
  // so the page never shows a half-rendered node descriptor.
  if (!id) {
    wrap.hidden = true;
    return;
  }
  wrap.hidden = false;
  modeEl.textContent = id.mode || '—';
  chips.replaceChildren();
  chips.append(chip('mining', !!id.mining), chip('extra-index', !!id.extra_index_enabled));
  // verify-tx is the validation-core signal; flag it like the others.
  const vtx = document.createElement('span');
  vtx.className = `pill ${id.verify_transactions ? 'pill--ok' : 'pill--warn'}`;
  vtx.textContent = id.verify_transactions ? 'verify-tx on' : 'verify-tx off';
  chips.append(vtx);
  // Bootstrap provenance is only meaningful when a jump actually ran;
  // surface a chip per active source rather than two perpetual "off"s.
  if (id.utxo_bootstrap) {
    const b = document.createElement('span');
    b.className = 'pill';
    b.textContent = 'utxo-bootstrapped';
    chips.append(b);
  }
  if (id.nipopow_bootstrap) {
    const b = document.createElement('span');
    b.className = 'pill';
    b.textContent = 'popow-bootstrapped';
    chips.append(b);
  }
}

// ---- KPI band (1 Hz) ----
export function onFast({ status, info }) {
  if (status) state.status = status;
  if (info) state.info = info;
  const s = state.status;
  const i = state.info;
  const tip = state.tip;
  if (!root) return;

  const blkH = s?.best_full_block_height ?? null;
  const hdrH = s?.best_header_height ?? null;
  setText('[data-k="height"]', num(blkH));
  setText(
    '[data-s="height"]',
    blkH != null && hdrH != null && blkH === hdrH ? 'at tip' : hdrH != null ? `gap ${num(hdrH - blkH)}` : '',
  );

  const tipMs = tip?.best_full_block?.timestamp_unix_ms ?? state.lastBlockMs;
  const ageS = tipMs ? Math.max(0, Math.floor((Date.now() - tipMs) / 1000)) : null;
  setText('[data-k="lastblk"]', ageS != null ? dur(ageS) : '—');
  if (hist.blockTimes.length >= 3) {
    const avg = hist.blockTimes.reduce((a, b) => a + b, 0) / hist.blockTimes.length;
    setText('[data-s="lastblk"]', `avg ${avg.toFixed(0)}s`);
  }

  const diff = parseDiff(tip?.best_header?.difficulty);
  setText('[data-k="diff"]', fmtDiff(diff));
  setText('[data-s="diff"]', diff != null ? diff.toExponential(2) : '');
  const hr = diff != null ? deriveHr(diff, i) : null;
  setText('[data-k="hr"]', hr != null ? fmtHr(hr) : '—');

  setText('[data-k="peers"]', num(s?.peer_count ?? 0));
  if (state.peerDist) setText('[data-s="peers"]', `${state.peerDist.out} out · ${state.peerDist.in} in`);

  setText('[data-k="mp"]', num(s?.mempool_size ?? 0));

  setText('[data-k="up"]', i ? dur(i.uptime_seconds) : '—');
  setText('[data-s="up"]', 'since restart');
}

// ---- data + quadrant (4 s) ----
export async function onSlow() {
  const [tip, sync, indexer, mempool, peers, recent, host] = await Promise.all([
    api.tip(),
    api.sync(),
    api.indexedHeight(),
    api.mempoolSummary(),
    api.peers(),
    api.recentBlocks(10),
    api.host(),
  ]);
  if (tip) state.tip = tip;

  // history buffers
  if (state.status) {
    push(hist.height, state.status.best_full_block_height);
    push(hist.mempool, state.status.mempool_size);
  }
  if (tip?.best_full_block) {
    const h = tip.best_full_block.height;
    const ms = tip.best_full_block.timestamp_unix_ms;
    if (state.lastHeight != null && h > state.lastHeight && state.lastBlockMs != null) {
      const dt = (ms - state.lastBlockMs) / 1000;
      if (dt > 0 && dt < 36000) push(hist.blockTimes, dt);
    }
    state.lastHeight = h;
    state.lastBlockMs = ms;
  }
  const diff = parseDiff(tip?.best_header?.difficulty);
  if (diff != null) push(hist.difficulty, diff);

  // peer distribution
  if (Array.isArray(peers)) {
    state.peerDist = {
      out: peers.filter((p) => p.direction === 'outbound').length,
      in: peers.filter((p) => p.direction === 'inbound').length,
      handshaking: peers.filter((p) => p.state === 'handshaking').length,
      total: peers.length,
    };
  }

  state._slow = { sync, indexer, mempool, recent, host };
  renderBody();
  // refresh KPI subs that depend on slow data
  if (state.status) onFast({ status: state.status, info: state.info });
}

function panel(title, openHash) {
  const p = document.createElement('section');
  p.className = 'panel ov-panel';
  const head = document.createElement('div');
  head.className = 'panel__head';
  const t = document.createElement('span');
  t.className = 'micro-label';
  t.textContent = title;
  head.append(t);
  if (openHash) {
    const a = document.createElement('a');
    a.className = 'ov-open';
    a.href = openHash;
    a.textContent = '↗ open';
    head.append(a);
  }
  const body = document.createElement('div');
  body.className = 'panel__body ov-panel__body';
  p.append(head, body);
  return { panel: p, body };
}

function bar(segments) {
  // segments: [{frac, color}]
  const wrap = document.createElement('div');
  wrap.className = 'distbar';
  for (const s of segments) {
    const d = document.createElement('div');
    d.style.width = `${Math.max(0, s.frac * 100)}%`;
    d.style.background = s.color;
    wrap.append(d);
  }
  return wrap;
}

function pipeRow(label, valTxt, frac, color) {
  const row = document.createElement('div');
  row.className = 'pipe';
  const l = document.createElement('span');
  l.className = 'pipe__l';
  l.textContent = label;
  const v = document.createElement('span');
  v.className = 'pipe__v';
  v.textContent = valTxt;
  const g = document.createElement('div');
  g.className = 'gauge';
  const pct = Math.round(Math.max(0, Math.min(100, frac * 100)));
  g.setAttribute('role', 'progressbar');
  g.setAttribute('aria-valuemin', '0');
  g.setAttribute('aria-valuemax', '100');
  g.setAttribute('aria-valuenow', String(pct));
  g.setAttribute('aria-label', label);
  const f = document.createElement('div');
  f.className = 'gauge__fill';
  f.style.width = `${Math.max(0, Math.min(100, frac * 100))}%`;
  if (color) f.style.background = color;
  g.append(f);
  row.append(l, v, g);
  return row;
}

function kv(label, value, color) {
  const r = document.createElement('div');
  r.className = 'ov-kv';
  const l = document.createElement('span');
  l.textContent = label;
  const v = document.createElement('span');
  v.textContent = value;
  if (color) v.style.color = color;
  r.append(l, v);
  return r;
}

function renderBody() {
  if (!root) return;
  const host = root.querySelector('.ov-body');
  if (!host) return;
  host.replaceChildren();
  if (viewMode === 'charts') {
    renderCharts(host);
    return;
  }
  const slow = state._slow || {};
  const grid = document.createElement('div');
  grid.className = 'quad';

  // Sync
  {
    const { panel: p, body } = panel('Sync pipeline');
    const sync = slow.sync;
    const idx = slow.indexer;
    const hdrH = sync?.best_header_height ?? 0;
    const blkH = sync?.best_full_block_height ?? 0;
    body.append(
      pipeRow('headers', num(hdrH), sync?.headers_chain_synced ? 1 : 0, 'var(--green)'),
      pipeRow('blocks', num(blkH), hdrH > 0 ? blkH / hdrH : 0, 'var(--green)'),
      pipeRow('indexer', idx ? num(idx.indexedHeight) : 'off', idx && hdrH > 0 ? idx.indexedHeight / hdrH : 0, 'var(--blue)'),
    );
    const foot = document.createElement('div');
    foot.className = 'ov-foot';
    foot.textContent = sync
      ? `gap ${num(sync.gap)} · window ${num(sync.download_window)} · pending ${num(sync.pending_blocks)}`
      : '—';
    if (hist.blockTimes.length > 1) foot.append(sparkline(hist.blockTimes, { color: 'var(--orange)' }));
    body.append(foot);
    grid.append(p);
  }
  // Network
  {
    const { panel: p, body } = panel('Network / Peers', '#peers');
    const d = state.peerDist;
    const big = document.createElement('div');
    big.className = 'ov-big';
    big.textContent = d ? String(d.total) : '—';
    body.append(big);
    if (d && d.total > 0) {
      body.append(
        bar([
          { frac: d.out / d.total, color: 'var(--blue)' },
          { frac: d.in / d.total, color: 'var(--purple)' },
        ]),
      );
      const sub = document.createElement('div');
      sub.className = 'ov-foot';
      sub.textContent = `out ${d.out} · in ${d.in}${d.handshaking ? ` · handshaking ${d.handshaking}` : ''}`;
      body.append(sub);
    }
    grid.append(p);
  }
  // Mempool
  {
    const { panel: p, body } = panel('Mempool', '#mempool');
    const mp = slow.mempool;
    if (mp) {
      const pct = mp.capacity_count > 0 ? mp.size / mp.capacity_count : 0;
      body.append(
        kv(`slots ${num(mp.size)} / ${num(mp.capacity_count)}`, `${(pct * 100).toFixed(0)}%`, 'var(--tx2)'),
      );
      const g = document.createElement('div');
      g.className = 'gauge';
      g.setAttribute('role', 'progressbar');
      g.setAttribute('aria-valuemin', '0');
      g.setAttribute('aria-valuemax', '100');
      g.setAttribute('aria-valuenow', String(Math.round(Math.min(100, pct * 100))));
      g.setAttribute('aria-label', 'mempool capacity');
      const f = document.createElement('div');
      f.className = 'gauge__fill';
      f.style.width = `${Math.min(100, pct * 100)}%`;
      g.append(f);
      body.append(g);
      const byteFoot = document.createElement('div');
      byteFoot.className = 'ov-foot';
      byteFoot.textContent = `bytes ${bytes(mp.total_bytes)} / ${bytes(mp.capacity_bytes)} (local budget)`;
      body.append(byteFoot);
    }
    if (hist.mempool.length > 1) {
      const sp = document.createElement('div');
      sp.className = 'ov-foot';
      sp.append(sparkline(hist.mempool, { color: 'var(--blue)' }));
      body.append(sp);
    }
    grid.append(p);
  }
  // Chain
  {
    const { panel: p, body } = panel('Chain tip · recent');
    const tip = state.tip;
    if (tip?.best_full_block) {
      body.append(
        kv(`tip ${num(tip.best_full_block.height)}`, dur(Math.max(0, Math.floor((Date.now() - tip.best_full_block.timestamp_unix_ms) / 1000))) + ' ago', 'var(--tx2)'),
      );
    }
    const list = document.createElement('div');
    list.className = 'ov-recent';
    const recent = slow.recent;
    if (Array.isArray(recent) && recent.length) {
      for (const b of recent.slice(0, 4)) {
        const row = document.createElement('div');
        row.className = 'ov-recent__r';
        const h = document.createElement('span');
        h.textContent = num(b.height);
        const m = document.createElement('span');
        m.textContent = `${b.txs} tx · ${bytes(b.size_bytes)} · ${dur(Math.floor((Date.now() - b.ts_unix_ms) / 1000))}`;
        row.append(h, m);
        list.append(row);
      }
    }
    body.append(list);
    grid.append(p);
  }

  host.append(grid);

  // sysbar
  const sb = document.createElement('div');
  sb.className = 'sysbar';
  const h = slow.host;
  const item = (label, val) => {
    const s = document.createElement('span');
    const l = document.createElement('span');
    l.className = 'sysbar__l';
    l.textContent = label + ' ';
    const v = document.createElement('b');
    v.textContent = val;
    s.append(l, v);
    return s;
  };
  sb.append(
    item('RSS', bytes(h?.rss_bytes)),
    item('disk free', bytes(h?.disk_free_bytes)),
    item('state.db', bytes(h?.state_db_bytes)),
    item('index.db', bytes(h?.index_db_bytes)),
  );
  host.append(sb);
}

function renderCharts(host) {
  const series = [
    ['Block height', hist.height, 'var(--green)'],
    ['Block time (s)', hist.blockTimes, 'var(--orange)'],
    ['Mempool depth', hist.mempool, 'var(--blue)'],
    ['Difficulty', hist.difficulty, 'var(--purple)'],
  ];
  const wrap = document.createElement('div');
  wrap.className = 'ov-charts';
  for (const [label, buf, color] of series) {
    const card = document.createElement('section');
    card.className = 'panel';
    const head = document.createElement('div');
    head.className = 'panel__head';
    const t = document.createElement('span');
    t.className = 'micro-label';
    t.textContent = label;
    const last = document.createElement('span');
    last.className = 'ov-foot';
    last.textContent = buf.length ? num(Math.round(buf[buf.length - 1])) : '—';
    head.append(t, last);
    const body = document.createElement('div');
    body.className = 'panel__body ov-chart';
    if (buf.length > 1) body.append(sparkline(buf, { color, h: 60 }));
    else body.textContent = 'warming up…';
    card.append(head, body);
    wrap.append(card);
  }
  host.append(wrap);
}
