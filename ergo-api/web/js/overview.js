// Overview cockpit: a no-scroll KPI band over a 2x2 quadrant + system
// strip, with a Cockpit/Charts toggle. KPI band updates at 1 Hz from the
// cheap status/info; the quadrant + sysbar rebuild on the 4 s slow tick.
import { api } from './api-client.js';
import { sparkline } from './sparkline.js';
import { lineChart, barChart } from './chart.js';
import { num, bytes, dur } from './format.js';
import { subscribe, promptAuthorize } from './auth.js';
import { minerNode, fetchOwnPk, ownPkHex } from './miners.js';
import { createChannelSub } from './ws-client.js';

const HISTORY_LEN = 60;
const HTTP_TIP_FALLBACK_MS = 30_000;
const WS_STALE_MS = 35_000;
const hist = { blockTimes: [], mempool: [], height: [], difficulty: [] };
const state = {
  status: null,
  info: null,
  tip: null,
  wsHeight: null,
  wsLastEventAt: 0,
  httpHeight: null,
  httpHeightAt: 0,
  identity: null,
  peerDist: null,
  lastBlockMs: null,
  lastHeight: null,
};
let root = null;
let viewMode = localStorage.getItem('ergo.ovview') || 'cockpit';
let derivedTick = null;

function handleBlocksFrame(frame) {
  if (frame.type !== 'event' || frame.channel !== 'blocks') return;
  if (frame.event !== 'block_applied' && frame.event !== 'reorg') return;
  const h = frame.height ?? frame.data?.height;
  if (h == null) return;
  state.wsHeight = h;
  state.wsLastEventAt = Date.now();
  push(hist.height, h);
  onFast({ status: state.status, info: state.info });
}

const blocksWs = createChannelSub({
  id: 'overview-blocks',
  channels: ['blocks'],
  onEvent: handleBlocksFrame,
});

/** Ages that can advance without a network round-trip (last block, uptime). */
function paintDerived() {
  if (!root) return;
  const tipMs = state.tip?.best_full_block?.timestamp_unix_ms ?? state.lastBlockMs;
  const ageS = tipMs ? Math.max(0, Math.floor((Date.now() - tipMs) / 1000)) : null;
  setText('[data-k="lastblk"]', ageS != null ? dur(ageS) : '—');
  const started = state.info?.started_at_unix_ms;
  if (started) {
    setText('[data-k="up"]', dur(Math.max(0, Math.floor((Date.now() - started) / 1000))));
  }
}

function startDerivedTick() {
  if (derivedTick) return;
  paintDerived();
  derivedTick = setInterval(paintDerived, 1000);
}

function stopDerivedTick() {
  if (!derivedTick) return;
  clearInterval(derivedTick);
  derivedTick = null;
}

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

function wsHeightFresh(now = Date.now()) {
  return state.wsHeight != null && (blocksWs.isConnected() || now - state.wsLastEventAt < WS_STALE_MS);
}

function noteHttpHeight(status) {
  const h = status?.best_full_block_height;
  if (h == null) return;
  const now = Date.now();
  if (state.httpHeight == null || now - state.httpHeightAt >= HTTP_TIP_FALLBACK_MS) {
    state.httpHeight = h;
    state.httpHeightAt = now;
  }
}

function displayHeight() {
  return wsHeightFresh() ? state.wsHeight : state.httpHeight ?? state.status?.best_full_block_height ?? null;
}

export function mount(el) {
  root = el;
  // One-shot own-pk probe (404s cache null on non-mining nodes) so the
  // recent-blocks mini-list can badge self-mined rows from first paint.
  fetchOwnPk();
  el.innerHTML = `
    <div class="ov-prompt banner banner--info" data-auth-prompt hidden></div>
    <div class="pg-head pg-head--flush ov-top">
      <div>
        <h1 class="pg-title">Node overview</h1>
        <div class="ov-ident" data-ident hidden>
          <span class="ov-ident__mode" data-ident-mode>—</span>
          <span class="ov-ident__chips" data-ident-chips></span>
        </div>
      </div>
      <div class="tabs ov-toggle" aria-label="overview view">
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
  blocksWs.start();
  startDerivedTick();
}

export function onShow() {
  blocksWs.start();
  startDerivedTick();
  if (state.status) onFast({ status: state.status, info: state.info });
}

export function onHide() {
  blocksWs.stop();
  stopDerivedTick();
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

  noteHttpHeight(s);
  const blkH = displayHeight();
  const rawHdrH = s?.best_header_height ?? null;
  const hdrH = rawHdrH != null || blkH != null ? Math.max(rawHdrH ?? blkH, blkH ?? rawHdrH) : null;
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

  // Prefer boot timestamp so uptime advances between rare /info refreshes.
  if (i?.started_at_unix_ms) {
    setText('[data-k="up"]', dur(Math.max(0, Math.floor((Date.now() - i.started_at_unix_ms) / 1000))));
  } else {
    setText('[data-k="up"]', i ? dur(i.uptime_seconds) : '—');
  }
  setText('[data-s="up"]', 'since restart');
}

// ---- data + quadrant (4 s) ----
export async function onSlow() {
  // Identity is normally fetched once on mount — but a transient failure
  // there would otherwise suppress identity-gated panels (mining) until a
  // remount. Retry on the slow tick while it's still missing.
  if (!state.identity) fetchIdentity();
  // Mining reads only when identity says mining is on (identity may still
  // be in flight the first tick — the calls start next tick).
  const miningOn = !!state.identity?.mining;
  const [tip, sync, indexer, indexerHealth, mempool, peers, recent, host, events, candidate, rewardAddr] =
    await Promise.all([
      api.tip(),
      api.sync(),
      api.indexedHeight(),
      api.indexerStatus(),
      api.mempoolSummary(),
      api.peers(),
      api.recentBlocks(10),
      api.host(),
      api.events(),
      miningOn ? api.miningCandidate() : null,
      // Reward address is static config — fetch once, then reuse.
      miningOn && !state.miningReward ? api.miningRewardAddress() : null,
    ]);
  if (tip) state.tip = tip;
  if (rewardAddr?.rewardAddress) state.miningReward = rewardAddr.rewardAddress;
  if (candidate) {
    // Track template turnover so the panel can show "refreshed Xs ago" —
    // template_seq bumps whenever the node rebuilds work for the miner.
    if (state.miningSeq !== candidate.template_seq) {
      state.miningSeq = candidate.template_seq;
      state.miningSeqAt = Date.now();
    }
    state.miningCandidate = candidate;
  } else if (miningOn) {
    // 503 window (no candidate / not synced / generation race): clear the
    // stale work rather than keep presenting old heights as current — the
    // panel renders its "no work available" state instead.
    state.miningCandidate = null;
  }

  // Mining-panel enrichment (mining nodes only): refetch the 720-block
  // miner fold + emission facts once per full-block tip advance — a 4s
  // cadence would hammer a 720-header fold for data that only changes
  // per block (same discipline as refreshChartData).
  if (miningOn) {
    const mtip = tip?.best_full_block?.height ?? 0;
    if (mtip && mtip !== state.minerStatsAt) {
      state.minerStatsAt = mtip;
      api.minerStats(720).then((s) => {
        if (s) state.minerStats = s;
      });
      api.emissionAt(mtip).then((e) => {
        if (e) state.emission = e;
      });
    }
  }

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

  state._slow = { sync, indexer, indexerHealth, mempool, recent, host, events };
  renderBody();
  // Charts view: refresh the server-history series when the tip advanced.
  if (viewMode === 'charts') refreshChartData();
  // refresh KPI subs that depend on slow data
  if (state.status) onFast({ status: state.status, info: state.info });
}

function panel(title, openHash) {
  const p = document.createElement('section');
  p.className = 'panel ov-panel';
  const head = document.createElement('div');
  head.className = 'panel__head';
  const t = document.createElement('span');
  t.className = 'panel__title';
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

// Footer link from the overview Mining panel into the full Mining section.
function miningSectionFoot() {
  const foot = document.createElement('div');
  foot.className = 'ov-foot';
  const a = document.createElement('a');
  a.className = 'ex-link';
  a.href = '#mining';
  a.textContent = 'Mining section →';
  foot.append(a);
  return foot;
}

function renderBody() {
  if (!root) return;
  const host = root.querySelector('.ov-body');
  if (!host) return;
  // Keyboard-safe rebuild: replacing the subtree while focus is inside it
  // dumps the user's focus to <body> on every 4s tick (the body now holds
  // links — recent blocks, mining reward, event heights). Defer the rebuild
  // to the next tick instead; one stale tick loses to keyboard usability.
  if (host.contains(document.activeElement)) return;
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
    // Extra-index health (self-repair markers from /api/v1/indexer/status).
    // Silent when healthy: rows appear only when there is something an
    // operator needs to see — a rebuild running, an honestly-incomplete
    // repair, or a halt.
    const ih = slow.indexerHealth;
    if (ih?.status === 'halted') {
      body.append(kv('index halted', ih.haltReason || 'unknown', 'var(--red)'));
    }
    if (ih?.repair?.pending) {
      const denom = ih.totals?.boxes ?? 0;
      const cur = ih.repair.nextGi;
      if (cur != null && denom > 0) {
        body.append(pipeRow('index repair', `${num(cur)} / ${num(denom)}`, cur / denom, 'var(--yellow)'));
      } else {
        body.append(kv('index repair', 'queued — wipe phase', 'var(--yellow)'));
      }
    } else if (ih?.repair?.skipped > 0) {
      // The honest marker: the rebuild completed but had to omit
      // undecodable boxes from the template/token indexes.
      body.append(kv('index repair', `done · ${num(ih.repair.skipped)} box(es) skipped`, 'var(--yellow)'));
    }
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
        // Height links into the explorer's block view (deep-linkable).
        const a = document.createElement('a');
        a.className = 'ex-link';
        a.href = `#explorer/block/${b.header_id}`;
        a.textContent = num(b.height);
        h.append(a);
        const m = document.createElement('span');
        m.textContent = `${b.txs} tx · ${bytes(b.size_bytes)} · ${dur(Math.floor((Date.now() - b.ts_unix_ms) / 1000))}`;
        if (b.miner_address) {
          m.append(document.createTextNode(' · '), minerNode(b.miner_address, b.miner_pk, { head: 4, tail: 4 }));
        }
        row.append(h, m);
        list.append(row);
      }
    }
    body.append(list);
    grid.append(p);
  }

  host.append(grid);

  // Mining + Events row: Mining renders only on mining-enabled nodes (the
  // /mining routes 404 elsewhere); Events takes the full width when alone.
  const duo = document.createElement('div');
  duo.className = 'ov-duo';
  if (state.identity?.mining) {
    const { panel: p, body } = panel('Mining');
    const c = state.miningCandidate;
    // Middle-ellipsize long ids; short/odd strings render verbatim rather
    // than as duplicated slices.
    const midTrunc = (s, head, tail) => (s && s.length > head + tail + 1 ? `${s.slice(0, head)}…${s.slice(-tail)}` : s || '—');
    if (c) {
      body.append(kv('work height', num(c.h), 'var(--tx2)'));
      if (state.miningSeqAt) {
        body.append(
          kv(
            `template #${num(c.template_seq)}`,
            `refreshed ${dur(Math.max(0, Math.floor((Date.now() - state.miningSeqAt) / 1000)))} ago`,
            'var(--tx2)',
          ),
        );
      }
      if (c.pk) body.append(kv('miner pk', midTrunc(c.pk, 10, 8), 'var(--tx3)'));
    } else {
      // Candidate 503s while the node has no work to hand out (syncing /
      // candidate generation race) — say so instead of showing stale work.
      body.append(kv('work', 'no candidate available (node syncing?)', 'var(--yellow)'));
    }
    if (state.miningReward) {
      const r = document.createElement('div');
      r.className = 'ov-kv';
      const l = document.createElement('span');
      l.textContent = 'reward address';
      const a = document.createElement('a');
      a.className = 'ex-link';
      a.href = `#explorer/address/${state.miningReward}`;
      a.textContent = midTrunc(state.miningReward, 10, 6);
      const v = document.createElement('span');
      v.append(a);
      r.append(l, v);
      body.append(r);
    }
    if (state.emission) {
      const base = Number(state.emission.minerReward) / 1e9;
      const re = Number(state.emission.reemitted || 0) / 1e9;
      body.append(kv('block reward', re ? `${base} + ${re} ERG` : `${base} ERG`, 'var(--tx2)'));
    }
    if (state.minerStats && ownPkHex()) {
      const mine = state.minerStats.miners.find((mm) => mm.pk === ownPkHex());
      body.append(
        kv(`your blocks · last ${num(state.minerStats.blocks)}`, String(mine?.count || 0), 'var(--tx2)'),
      );
    }
    body.append(miningSectionFoot());
    duo.append(p);
  } else if (state.identity && !state.identity.mining) {
    // Non-mining node: a one-line stub instead of hiding the panel — the
    // Mining section (network landscape) is still worth discovering. No
    // mining fetches happen in this state (see the miningOn gates above).
    const { panel: p, body } = panel('Mining');
    body.append(kv('mining', 'disabled', 'var(--tx3)'));
    body.append(miningSectionFoot());
    duo.append(p);
  }

  // Events feed: tail of the node's bounded event ring, newest first.
  // Silent kinds map to colored pills; block heights deep-link into the
  // explorer.
  {
    const feed = slow.events;
    if (feed && Array.isArray(feed.events) && feed.events.length) {
      const { panel: p, body } = panel('Events');
      const list = document.createElement('div');
      list.className = 'ov-events';
      for (const e of feed.events.slice(-10).reverse()) {
        const row = document.createElement('div');
        row.className = 'ov-events__r';
        const pill = document.createElement('span');
        pill.className = 'pill';
        const text = document.createElement('span');
        text.className = 'ov-events__t';
        if (e.kind === 'blockApplied') {
          pill.classList.add('pill--ok');
          pill.textContent = 'block';
          const a = document.createElement('a');
          a.className = 'ex-link';
          a.href = `#explorer/block/${e.headerId}`;
          a.textContent = num(e.height);
          text.append(a, ` · ${num(e.txs)} tx · ${bytes(e.sizeBytes)}`);
        } else if (e.kind === 'reorg') {
          pill.classList.add('pill--err');
          pill.textContent = 'reorg';
          text.textContent = `tip replaced at ${num(e.height)}`;
        } else if (e.kind === 'peerConnected') {
          pill.textContent = 'peer +';
          text.textContent = e.addr || '';
        } else if (e.kind === 'peerDisconnected') {
          pill.classList.add('pill--warn');
          pill.textContent = 'peer −';
          text.textContent = e.addr || '';
        } else if (e.kind === 'indexerStatus') {
          pill.classList.add('pill--warn');
          pill.textContent = 'index';
          text.textContent = e.detail || '';
        } else {
          pill.textContent = e.kind;
        }
        const when = document.createElement('span');
        when.className = 'ov-events__w';
        when.textContent = e.unixMs ? `${dur(Math.max(0, Math.floor((Date.now() - e.unixMs) / 1000)))} ago` : '';
        row.append(pill, text, when);
        list.append(row);
      }
      body.append(list);
      duo.append(p);
    }
  }
  if (duo.childElementCount) {
    duo.classList.toggle('ov-duo--solo', duo.childElementCount === 1);
    host.append(duo);
  }

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

// ---- charts view: real server-history charts (built once, updated in place
// so hover state and DOM survive the 4 s renderBody rebuild) ----

const charts = {
  wrap: null,
  diff: null,
  hr: null,
  intervals: null,
  fees: null,
  lastFetchHeight: 0,
  inFlight: false,
};

function chartCard(title, chart) {
  const card = document.createElement('section');
  card.className = 'panel';
  const head = document.createElement('div');
  head.className = 'panel__head';
  const t = document.createElement('span');
  t.className = 'panel__title';
  t.textContent = title;
  head.append(t);
  const body = document.createElement('div');
  body.className = 'panel__body';
  body.append(chart.el);
  card.append(head, body);
  return card;
}

function buildCharts() {
  charts.diff = lineChart({
    color: 'var(--purple)',
    xFmt: (h) => num(h),
    yFmt: fmtDiff,
    label: 'network difficulty',
  });
  charts.hr = lineChart({
    color: 'var(--orange)',
    xFmt: (h) => num(h),
    yFmt: fmtHr,
    label: 'estimated hashrate',
  });
  charts.intervals = barChart({
    color: 'var(--green)',
    yFmt: (v) => `${num(v)} blocks`,
    label: 'block-interval distribution',
  });
  charts.fees = barChart({
    color: 'var(--blue)',
    yFmt: (v) => `${num(v)} tx`,
    label: 'mempool wait-time histogram',
  });
  charts.wrap = document.createElement('div');
  charts.wrap.className = 'ov-charts';
  charts.wrap.append(
    chartCard('Difficulty · last 720 blocks', charts.diff),
    chartCard('Est. hashrate · last 720 blocks', charts.hr),
    chartCard('Block intervals · last 720 blocks', charts.intervals),
    chartCard('Mempool age histogram · waiting tx', charts.fees),
  );
}

// Bucket consecutive-block timestamp deltas into a readable histogram.
const INTERVAL_BINS = [
  ['<30s', 0, 30],
  ['30–60s', 30, 60],
  ['1–2m', 60, 120],
  ['2–3m', 120, 180],
  ['3–5m', 180, 300],
  ['5–10m', 300, 600],
  ['>10m', 600, Infinity],
];

async function refreshChartData() {
  const tipH = state.status?.best_full_block_height ?? 0;
  // Difficulty/intervals only change on a new block — skip refetch otherwise.
  const needSeries = tipH > 0 && tipH !== charts.lastFetchHeight;
  if (charts.inFlight) return;
  charts.inFlight = true;
  try {
    const [series, histo] = await Promise.all([
      needSeries ? api.difficultyHistory(720) : null,
      api.poolHistogram(12, 3_600_000),
    ]);
    if (series?.points?.length) {
      charts.lastFetchHeight = tipH;
      const pts = series.points;
      // difficulty is a STRING on the wire because it can exceed 2^53 —
      // Number() here is a DELIBERATE approximate parse: charts are visual,
      // a sub-ppm rounding above 2^53 is invisible at pixel scale. Exact
      // rendering (the explorer block view) keeps the string verbatim.
      charts.diff.update(pts.map((p) => ({ x: p.height, y: Number(p.difficulty) })));
      // Estimated hashrate = difficulty / target interval — same derivation
      // as the KPI band (deriveHr), applied per point.
      const tgtS = Math.max(1, (state.info?.target_block_interval_ms ?? 120000) / 1000);
      charts.hr.update(pts.map((p) => ({ x: p.height, y: Number(p.difficulty) / tgtS })));
      const bins = INTERVAL_BINS.map(([label]) => ({ label, value: 0 }));
      for (let i = 1; i < pts.length; i++) {
        const dt = (pts[i].timestamp_unix_ms - pts[i - 1].timestamp_unix_ms) / 1000;
        if (!(dt >= 0)) continue;
        const bi = INTERVAL_BINS.findIndex(([, lo, hi]) => dt >= lo && dt < hi);
        if (bi >= 0) bins[bi].value += 1;
      }
      charts.intervals.update(bins);
    }
    if (Array.isArray(histo)) {
      // bins+1 wait-time buckets of {nTxns, totalFee}, oldest-waiting last.
      const stepMin = 3_600_000 / 12 / 60_000;
      charts.fees.update(
        histo.map((b, i) => ({
          label: i < 12 ? `${Math.round(i * stepMin)}–${Math.round((i + 1) * stepMin)}m` : `>${Math.round(12 * stepMin)}m`,
          value: b.nTxns ?? 0,
        })),
      );
    }
  } finally {
    charts.inFlight = false;
  }
}

function renderCharts(host) {
  if (!charts.wrap) {
    buildCharts();
    refreshChartData();
  }
  host.append(charts.wrap);
}
