// Mining section: this node's mining state + the network mining landscape.
// Always visible — the network panels are meaningful on any node; the
// "Your node" panel shows an explicit disabled state when identity.mining
// is false. Network series follow the header tip; recently applied blocks
// follow the local full-block tip independently while syncing.
import { subscribe, CONFIGURE_API_KEY } from './auth.js';
import { api } from './api-client.js';
import { makeTable } from './table.js';
import { erg, num, bytes, dur, truncMiddle, blockTime } from './format.js';
import { minerNode, poolLabel, fetchOwnPk, ownPkHex } from './miners.js';

const EPOCH = 128; // EIP-37 difficulty-adjustment period (blocks)

let els = null;
let recentTable = null;
let identity = null;
let candidate = null;
let candidateSeq = null;
let candidateSeqAt = null;
let rewardAddr = null;
let info = null;
let tip = null;
let stats = null; // minerStats for the selected window
let emission = null;
let recentRows = [];
let lastFetchTip = 0;
let lastRecentTip = 0;
let nodeSyncState = null;
let distWindow = 720;

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text != null) e.textContent = text;
  return e;
}

// Label/value row (overview's .ov-kv vocabulary). `value` may be a Node.
function kvNode(label, value, color) {
  const r = el('div', 'ov-kv');
  const l = el('span', null, label);
  const v = el('span');
  if (value instanceof Node) v.append(value);
  else v.textContent = value == null ? '—' : String(value);
  if (color) v.style.color = color;
  r.append(l, v);
  return r;
}

function hashrate(h) {
  if (!Number.isFinite(h) || h <= 0) return '—';
  const u = ['H/s', 'kH/s', 'MH/s', 'GH/s', 'TH/s', 'PH/s', 'EH/s'];
  let i = 0;
  let v = h;
  while (v >= 1000 && i < u.length - 1) {
    v /= 1000;
    i++;
  }
  return `${v.toFixed(2)} ${u[i]}`;
}

export function mount(elRoot) {
  elRoot.innerHTML = `
    <div class="pg-head">
      <div>
        <h1 class="pg-title">Mining</h1>
        <p class="pg-description">Your mining readiness and the network seen through your node's headers.</p>
        <span class="pg-count micro-label" data-sub></span>
      </div>
    </div>
    <p class="muted" data-configure-key hidden></p>
    <div class="mn-grid">
      <section class="panel">
        <div class="panel__head"><h2 class="panel__title">Your node</h2></div>
        <div class="panel__body" data-you></div>
      </section>
      <section class="panel">
        <div class="panel__head"><h2 class="panel__title">Network</h2></div>
        <div class="panel__body" data-net></div>
      </section>
      <section class="panel mn-full">
        <div class="panel__head">
          <h2 class="panel__title">Miner distribution</h2>
          <span class="mn-win" data-win></span>
        </div>
        <div class="panel__body" data-dist></div>
      </section>
      <section class="panel mn-full">
        <div class="panel__head"><h2 class="panel__title">Recently applied blocks · local chain</h2></div>
        <div class="panel__body" data-recent></div>
      </section>
    </div>`;
  subscribe((s) => {
    const guidance = elRoot.querySelector('[data-configure-key]');
    guidance.hidden = s !== 'unconfigured';
    guidance.textContent = CONFIGURE_API_KEY;
  });
  els = {
    sub: elRoot.querySelector('[data-sub]'),
    you: elRoot.querySelector('[data-you]'),
    net: elRoot.querySelector('[data-net]'),
    win: elRoot.querySelector('[data-win]'),
    dist: elRoot.querySelector('[data-dist]'),
    recent: elRoot.querySelector('[data-recent]'),
  };
  for (const w of [128, 720]) {
    const b = el('button', 'btn', String(w));
    b.type = 'button';
    b.setAttribute('aria-pressed', String(w === distWindow));
    b.onclick = () => {
      if (distWindow === w) return;
      distWindow = w;
      for (const x of els.win.children) {
        x.setAttribute('aria-pressed', String(x.textContent === String(w)));
      }
      refetchStats();
    };
    els.win.append(b);
  }
  recentTable = makeTable(
    els.recent,
    [
      { key: 'height', label: 'Height', width: 90, render: (b) => blockLink(b, num(b.height)), sort: (b) => b.height },
      { key: 'age', label: 'Mined', width: 116, align: 'right', render: (b) => blockTime(b.ts_unix_ms), sort: (b) => -b.ts_unix_ms },
      { key: 'txs', label: 'Txs', width: 60, align: 'right', sort: (b) => b.txs },
      { key: 'size', label: 'Size', width: 80, align: 'right', render: (b) => bytes(b.size_bytes), sort: (b) => b.size_bytes },
      { key: 'miner', label: 'Miner', width: 150, render: (b) => minerNode(b.miner_address, b.miner_pk), sort: (b) => poolLabel(b.miner_address) || b.miner_address || '' },
      { key: 'id', label: 'Block ID', render: (b) => blockLink(b, truncMiddle(b.header_id, 8, 8)), sort: (b) => b.header_id },
    ],
    { rowKey: (b) => b.header_id, initialSort: { key: 'height', dir: -1 } },
  );
  fetchOwnPk();
}

function blockLink(b, label) {
  const a = el('a', 'ex-link', label);
  a.href = `#explorer/block/${b.header_id}`;
  return a;
}

async function refetchStats() {
  // Window-race guard: a toggle can overlap onSlow's per-tip fetch (that
  // one runs outside this call), so commit a response only if the window
  // it was requested for is still the selected one at arrival time.
  const w = distWindow;
  const s = await api.minerStats(w);
  if (s && w === distWindow) {
    stats = s;
    render();
  }
}

export async function onSlow() {
  if (!identity) identity = await api.identity();
  const miningOn = !!identity?.mining;
  const [tipNow, infoNow, cand, rew] = await Promise.all([
    api.tip(),
    info ? null : api.info(),
    miningOn ? api.miningCandidate() : null,
    miningOn && !rewardAddr ? api.miningRewardAddress() : null,
  ]);
  if (tipNow) tip = tipNow;
  if (infoNow) info = infoNow;
  if (rew?.rewardAddress) rewardAddr = rew.rewardAddress;
  if (cand) {
    if (candidateSeq !== cand.template_seq) {
      candidateSeq = cand.template_seq;
      candidateSeqAt = Date.now();
    }
    candidate = cand;
  } else if (miningOn) {
    // Candidate 503s while the node has no work to hand out (syncing /
    // generation race) — clear stale work; render shows the honest state.
    candidate = null;
  }

  // Network statistics are header-based. A historical full-block tip would
  // show an old block reward alongside today's difficulty while syncing.
  const tipH = tip?.best_header?.height ?? 0;
  if (tipH && tipH !== lastFetchTip) {
    const w = distWindow;
    const [s, em] = await Promise.all([
      api.minerStats(w),
      api.emissionAt(tipH),
    ]);
    // Same window-race guard as refetchStats: don't let a stale-window
    // response (dispatched before a toggle) overwrite the fresh one.
    if (s && w === distWindow) stats = s;
    if (em) emission = em;
    if (s && em) lastFetchTip = tipH;
  }
  const fullH = tip?.best_full_block?.height ?? 0;
  if (fullH && fullH !== lastRecentTip) {
    const recent = await api.recentBlocks(32);
    if (Array.isArray(recent)) { recentRows = recent; lastRecentTip = fullH; }
  }
  render();
}

export function onFast({ status }) {
  if (status) nodeSyncState = status.sync_state;
}

function render() {
  if (!els) return;
  els.sub.textContent = stats
    ? `${stats.miners.length} miners · ${num(stats.blocks)} headers through height ${num(stats.tip_height)}`
    : '';

  // ---- Your node ----
  els.you.replaceChildren();
  if (!identity) {
    els.you.append(el('div', 'micro-label', 'loading…'));
  } else if (!identity.mining) {
    els.you.append(kvNode('mining', 'disabled', 'var(--tx3)'));
    els.you.append(
      el(
        'div',
        'micro-label',
        'This node does not serve mining work. Enable mining in the node config (mining = true) to hand out candidates to external miners.',
      ),
    );
  } else {
    els.you.append(kvNode('mining', 'enabled', 'var(--green)'));
    if (candidate) {
      els.you.append(kvNode('work height', num(candidate.h), 'var(--tx2)'));
      if (candidateSeqAt) {
        els.you.append(
          kvNode(
            `template #${num(candidate.template_seq)}`,
            `refreshed ${dur(Math.max(0, Math.floor((Date.now() - candidateSeqAt) / 1000)))} ago`,
            'var(--tx2)',
          ),
        );
      }
      if (candidate.pk) {
        els.you.append(kvNode('miner pk', truncMiddle(candidate.pk, 10, 8), 'var(--tx3)'));
      }
    } else {
      els.you.append(kvNode('Work status', nodeSyncState === 'syncing' ? 'Waiting for chain sync' : 'No candidate available', 'var(--yellow)'));
      if (nodeSyncState === 'syncing') {
        const syncLink = el('a', 'ex-link', 'View sync progress →');
        syncLink.href = '#overview';
        els.you.append(syncLink);
      }
    }
    if (rewardAddr) {
      const a = el('a', 'ex-link', truncMiddle(rewardAddr, 10, 6));
      a.href = `#explorer/address/${rewardAddr}`;
      els.you.append(kvNode('reward address', a));
    }
    if (stats && ownPkHex()) {
      const mine = stats.miners.find((m) => m.pk === ownPkHex());
      els.you.append(
        kvNode(`your blocks · last ${num(stats.blocks)}`, String(mine?.count || 0), 'var(--tx2)'),
      );
    }
    const foot = el('div', 'ov-foot');
    const wl = el('a', 'ex-link', 'matured rewards → Wallet');
    wl.href = '#wallet';
    foot.append(wl);
    els.you.append(foot);
  }

  // ---- Network ----
  els.net.replaceChildren();
  const diffStr = tip?.best_header?.difficulty;
  // difficulty is a decimal string that can exceed 2^53 — show verbatim.
  els.net.append(kvNode('difficulty', diffStr ?? '—'));
  const tgtS = Math.max(1, (info?.target_block_interval_ms ?? 120000) / 1000);
  if (diffStr != null) {
    // Approximate parse is fine at display precision (chart.js precedent);
    // the verbatim string is one row above.
    els.net.append(kvNode('est. network hashrate', hashrate(Number(diffStr) / tgtS)));
  }
  const tipH = tip?.best_header?.height ?? 0;
  if (tipH) {
    const toGo = EPOCH - (tipH % EPOCH);
    els.net.append(kvNode('Header height', num(tipH)));
    els.net.append(kvNode('Next difficulty epoch', `${num(toGo)} blocks · ${dur(Math.round(toGo * tgtS))} at target pace`));
  }
  if (emission) {
    const base = Number(emission.minerReward) / 1e9;
    const re = Number(emission.reemitted || 0) / 1e9;
    els.net.append(
      kvNode('Reward at header height', re ? `${base} + ${re} ERG (re-emission)` : `${base} ERG`, 'var(--tx2)'),
    );
    const issued = Number(emission.totalCoinsIssued);
    const remain = Number(emission.totalRemainCoins);
    if (issued > 0) {
      els.net.append(
        kvNode(
          'supply issued',
          `${erg(emission.totalCoinsIssued)} ERG · ${((100 * issued) / (issued + remain)).toFixed(2)}%`,
        ),
      );
    }
  }

  // ---- Miner distribution ----
  els.dist.replaceChildren();
  if (!stats?.miners?.length) {
    els.dist.append(el('div', 'micro-label', 'no data yet'));
  } else {
    const total = stats.blocks || stats.miners.reduce((a, m) => a + m.count, 0);
    for (const m of stats.miners) {
      const row = el('div', 'mn-row');
      const label = el('span', 'mn-row__label');
      label.append(minerNode(m.address, m.pk, { head: 8, tail: 6 }));
      const bar = el('div', 'mn-bar');
      const fill = el('div', 'mn-bar__fill');
      const pct = total ? (100 * m.count) / total : 0;
      fill.style.width = `${pct}%`;
      bar.append(fill);
      row.append(label, bar, el('span', 'mn-row__count', `${num(m.count)} · ${pct.toFixed(1)}%`));
      els.dist.append(row);
    }
  }

  // ---- Recent blocks ----
  recentTable.update(recentRows);
}
