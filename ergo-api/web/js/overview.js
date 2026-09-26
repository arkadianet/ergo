// Overview: sync first, then operational metrics and detailed activity.
// The summary is patched in place; detailed panels use the slow tick.
import { api } from './api-client.js';
import { lineChart, barChart } from './chart.js';
import { num, bytes, dur } from './format.js';
import { subscribe, promptAuthorize } from './auth.js';
import { fetchOwnPk, ownPkHex } from './miners.js';
import { createChannelSub } from './ws-client.js';
import { blockRejectionState, hasActiveNodeIssue, nodeGuidance } from './node-guidance.js';
import { recentChain, nodeEvents } from './chain-activity.js';
import { syncLayers } from './sync-rings.js';
import { miningWork } from './mining-work.js';
import { miningReward } from './mining-reward.js';
import { createRentSource, rentForecastView } from './storage-rent.js';

const rentSource = createRentSource(api);

const HISTORY_LEN = 60;
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
  reachable: null,
};
let root = null;
let viewMode = localStorage.getItem('ergo.ovview') || 'cockpit';
let derivedTick = null;
let progressSamples = [];

function recordProgress(height, now = Date.now()) {
  if (!Number.isFinite(height) || state.reachable === false) return;
  const last = progressSamples.at(-1);
  // A reorg, restart, or long pause must not manufacture a throughput spike.
  if (last && (height < last.height || now - last.time > 15000)) progressSamples = [];
  if (!progressSamples.length || now - progressSamples.at(-1).time >= 1000) {
    progressSamples.push({ height, time: now });
    progressSamples = progressSamples.filter((p) => now - p.time <= 60000);
  }
}

function recentPace(now = Date.now()) {
  const first = progressSamples[0];
  const last = progressSamples.at(-1);
  if (!first || !last || now - last.time > 15000 || last.time - first.time < 10000) return null;
  return { rate: (last.height - first.height) / ((last.time - first.time) / 1000), seconds: Math.round((last.time - first.time) / 1000) };
}

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
  const historical = state.status?.sync_state !== 'at_tip' && ageS > 86400;
  setText('[data-label="lastblk"]', historical ? 'Local block date' : 'Local block age');
  setText('[data-k="lastblk"]', tipMs && historical
    ? new Date(tipMs).toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' })
    : ageS != null ? dur(ageS) : '—');
  setText('[data-s="lastblk"]', historical ? 'Historical chain data' : 'Since this block was mined');
  const started = state.info?.started_at_unix_ms;
  if (started) {
    setText('[data-k="up"]', dur(Math.max(0, Math.floor((Date.now() - started) / 1000))));
  }
  const pace = state.reachable === false ? null : recentPace();
  const atTip = state.reachable !== false && state.status?.sync_state === 'at_tip';
  setText('[data-pace-label]', atTip ? 'Chain activity' : 'Processing pace');
  setText('[data-sync-pace]', state.reachable === false ? 'Unavailable' : atTip ? 'Following the chain' : pace ? `${pace.rate.toFixed(1)} blocks/s` : 'Measuring…');
  setText('[data-sync-pace-note]', state.reachable === false ? 'Unavailable while disconnected' : atTip ? 'Idle time between blocks is normal' : pace ? `Observed over ${pace.seconds}s · not an ETA` : 'Requires 10 seconds of continuous data');
  const duration = state.status?.last_apply_duration_ms;
  setText('[data-apply-duration]', state.status?.last_applied_height > 0 && duration != null ? `${num(duration)} ms` : '—');
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
  ['peers', 'Connected peers', '#peers'],
  ['mp', 'Pending transactions', '#mempool'],
  ['lastblk', 'Local block age'],
  ['up', 'Node uptime'],
];

function setText(sel, t) {
  const e = root && root.querySelector(sel);
  if (e && e.textContent !== String(t)) e.textContent = t;
}

function wsHeightFresh(now = Date.now()) {
  // Freshness is time-based only: a reconnect must not revive a stale tip.
  return state.wsHeight != null && now - state.wsLastEventAt < WS_STALE_MS;
}

function noteHttpHeight(status) {
  const h = status?.best_full_block_height;
  if (h == null) return;
  const now = Date.now();
  state.httpHeight = h;
  state.httpHeightAt = now;
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
    <div class="pg-head pg-head--flush ov-top">
      <div>
        <div class="ov-eyebrow">NODE WORKSPACE</div>
        <h1 class="pg-title">Overview</h1>
        <p class="ov-intro">Chain progress, service readiness and recent activity.</p>
        <div class="ov-ident" data-ident hidden>
          <span class="ov-ident__mode" data-ident-mode>—</span>
          <span class="ov-ident__chips" data-ident-chips></span>
        </div>
      </div>
      <div class="tabs ov-toggle" role="group" aria-label="overview view">
        <button class="tab" type="button" data-view="cockpit">Overview</button>
        <button class="tab" type="button" data-view="charts">Chain analytics</button>
      </div>
    </div>
    <section class="ov-sync" aria-label="Synchronization status" data-sync-tone="loading">
      <div class="ov-sync__summary">
      <div class="ov-sync__top">
        <div>
          <div class="ov-sync__status" role="status" data-sync-label>Connecting to your node</div>
          <h2 data-sync-title>Waiting for sync status</h2>
          <p data-sync-copy>Progress will appear when the node responds.</p>
          <button class="btn btn--ghost ov-sync__action" type="button" data-guidance-action hidden></button>
        </div>
        <div class="ov-sync__percent">
          <svg class="ov-orbit ov-orbit--layers" viewBox="0 0 220 220" role="img" aria-label="Waiting for sync stage data" data-sync-rings>
            ${[['headers', 99], ['blocks', 90], ['index', 81]].map(([id, radius]) => `<circle class="ov-orbit__base" cx="110" cy="110" r="${radius}"/><circle class="ov-orbit__value" data-ring="${id}" data-state="unknown" cx="110" cy="110" r="${radius}" pathLength="100" stroke-dasharray="0 100"/>`).join('')}
          </svg>
          <div class="ov-orbit__label"><span class="ov-orbit__caption">BLOCKS</span><strong data-sync-percent>—</strong><span>of headers</span></div>
        </div>
      </div>
      <div class="ov-ring-legend" aria-label="Sync stages, outer to inner">
        ${[['headers', 'Headers', 'Outer'], ['blocks', 'Blocks', 'Middle'], ['index', 'Search index', 'Inner']].map(([id, label, position]) => `<div data-ring-legend="${id}" data-state="unknown"><span class="ov-ring-legend__name">${label}<small>${position}</small></span><strong data-ring-state="${id}">Unavailable</strong></div>`).join('')}
      </div>
      <div class="gauge ov-sync__track" role="progressbar" aria-label="Blocks applied against known headers" aria-valuemin="0" aria-valuemax="100" data-sync-progress><div class="gauge__fill" data-sync-fill></div></div>
      <div class="ov-sync__bottom">
        <span><b data-k="height">—</b> <span class="muted">blocks applied /</span> <b data-sync-target>—</b></span>
        <span data-sync-remaining>Waiting for data</span>
      </div>
      </div>
      <div class="ov-sync__insights">
        <div><span class="ov-insight-label" data-pace-label>Processing pace</span><strong data-sync-pace>Measuring…</strong><span data-sync-pace-note>Requires 10 seconds of continuous data</span></div>
        <div><span class="ov-insight-label">Last block processing</span><strong data-apply-duration>—</strong><span>Time spent applying one block</span></div>
        <div><span class="ov-insight-label">Search index</span><strong data-index-state>Checking…</strong><span data-index-note>Address, box and token lookup availability</span></div>
      </div>
    </section>
    <div class="ov-alerts" data-node-alerts role="status" hidden></div>
    <details class="ov-diagnostics" data-node-diagnostics hidden>
      <summary><span class="ov-diagnostics__title" data-diagnostics-title></span><span class="ov-diagnostics__meta" data-diagnostics-meta></span></summary>
      <div class="ov-diagnostics__body">
        <dl class="ov-diagnostics__status">
          <dt>API</dt><dd data-diagnostic-connection></dd><dt>Chain</dt><dd data-diagnostic-chain></dd>
          <dt>Headers</dt><dd data-diagnostic-headers></dd><dt>Applied</dt><dd data-diagnostic-applied></dd>
          <dt>Peers</dt><dd data-diagnostic-peers></dd><dt>Search index</dt><dd data-diagnostic-index></dd>
        </dl>
        <p class="ov-diagnostics__issues" data-diagnostic-issues></p>
        <p data-diagnostic-index-issues hidden></p>
        <section data-rejection-details hidden>
          <h3>Last block rejection</h3><p class="muted" data-rejection-meta></p>
          <p data-rejection-progress></p>
          <dl><dt>Block ID</dt><dd><code data-rejection-id></code></dd><dt>Reason</dt><dd data-rejection-reason></dd></dl>
          <p class="muted">Retained for diagnosis. Chain progress does not establish why this block was rejected; the node logs contain the validation context.</p>
        </section>
      </div>
    </details>
    <div class="kpi">
      ${KPI.map(
        ([k, l, href]) =>
          `<${href ? `a href="${href}"` : 'div'} class="kpi__t"><div class="micro-label"><span data-label="${k}">${l}</span>${href ? '<span aria-hidden="true">↗</span>' : ''}</div>` +
          `<div class="kpi__v" data-k="${k}">—</div>` +
          `<div class="kpi__s" data-s="${k}"></div></${href ? 'a' : 'div'}>`,
      ).join('')}
    </div>
    <div class="ov-body"></div>
    <div class="ov-prompt" data-auth-prompt hidden></div>`;
  el.querySelectorAll('.ov-toggle .tab').forEach((b) => {
    b.setAttribute('aria-pressed', String(b.dataset.view === viewMode));
    b.onclick = () => {
      viewMode = b.dataset.view;
      localStorage.setItem('ergo.ovview', viewMode);
      el.querySelectorAll('.ov-toggle .tab').forEach((x) =>
        x.setAttribute('aria-pressed', String(x.dataset.view === viewMode)),
      );
      renderBody();
    };
  });
  el.querySelector('[data-guidance-action]').onclick = () => {
    const destination = el.querySelector('[data-guidance-action]').dataset.destination;
    if (destination === 'diagnostics') {
      const details = el.querySelector('[data-node-diagnostics]');
      details.hidden = false;
      details.open = true;
      const summary = details.querySelector('summary');
      summary.focus({ preventScroll: true });
      summary.scrollIntoView({ block: 'start', behavior: 'instant' });
    } else if (destination) location.hash = destination;
  };
  // Authorize prompt: visible only while no api_key is set. Built once; the
  // subscription just toggles visibility as the auth state changes.
  const prompt = root.querySelector('[data-auth-prompt]');
  if (prompt) {
    const txt = document.createElement('span');
    txt.textContent = 'Read-only access · Authorize to manage voting and your wallet.';
    const btn = document.createElement('button');
    btn.className = 'btn btn--ghost btn--sm';
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
export function onFast({ status, info, reachable }) {
  if (reachable !== undefined) state.reachable = reachable;
  if (info?.started_at_unix_ms && state.info?.started_at_unix_ms && info.started_at_unix_ms !== state.info.started_at_unix_ms) {
    progressSamples = [];
    state.wsHeight = null;
    state.httpHeight = null;
  }
  if (status) state.status = status;
  if (info) state.info = info;
  const s = state.status;
  const i = state.info;
  if (!root) return;

  noteHttpHeight(s);
  const blkH = displayHeight();
  const rawHdrH = s?.best_header_height ?? null;
  const hdrH = rawHdrH != null ? Math.max(rawHdrH, blkH ?? 0) : null;
  const idx = state._slow?.indexer;
  const guidance = nodeGuidance({ reachable: state.reachable, status: s, indexer: idx, indexerHealth: state._slow?.indexerHealth, identity: state.identity });
  setText('[data-k="height"]', num(blkH));
  recordProgress(blkH);
  paintSyncSummary(blkH, hdrH, guidance);
  paintSyncRings();
  paintAlerts(guidance);
  paintDerived();

  setText('[data-k="peers"]', num(s?.peer_count));
  if (state.peerDist) setText('[data-s="peers"]', `${state.peerDist.out} out · ${state.peerDist.in} in`);

  setText('[data-k="mp"]', num(s?.mempool_size));
  const mp = state._slow?.mempool;
  setText('[data-s="mp"]', mp ? `${bytes(mp.total_bytes)} / ${bytes(mp.capacity_bytes)} capacity` : 'Awaiting mempool data');

  // Prefer boot timestamp so uptime advances between rare /info refreshes.
  if (i?.started_at_unix_ms) {
    setText('[data-k="up"]', dur(Math.max(0, Math.floor((Date.now() - i.started_at_unix_ms) / 1000))));
  } else {
    setText('[data-k="up"]', i ? dur(i.uptime_seconds) : '—');
  }
  setText('[data-s="up"]', 'Since last restart');
  const idxState = state.reachable === false ? 'Last known data' : idx?.status === 'caughtUp' ? 'Available' : idx?.status === 'halted' ? 'Needs attention' : idx ? 'Catching up' : state.identity?.extra_index_enabled === false ? 'Disabled' : 'Unavailable';
  setText('[data-index-state]', idxState);
  setText('[data-index-note]', idx ? `Indexed ${num(idx.indexedHeight)} of ${num(idx.fullHeight ?? blkH)} applied blocks` : 'Address, box and token lookups need the index');
}

function paintAlerts(guidance) {
  const host = root.querySelector('[data-node-alerts]');
  if (!host) return;
  const s = state.status;
  const rejection = blockRejectionState(s);
  const alerts = [];
  if (s?.sync_wedged) alerts.push('Chain sync is blocked by a deep fork. Review the node logs and recovery procedure before taking action.');
  if (s?.apply_wedged) alerts.push('A block is taking longer than the node’s processing threshold. Inspect the node logs.');
  if (s?.last_storage_error) alerts.push(`Storage error reported: ${s.last_storage_error}`);
  if (rejection === 'unresolved') alerts.push(`Block validation rejected a block${s.last_block_apply_error.height != null ? ` at height ${num(s.last_block_apply_error.height)}` : ''}. Recovery is not yet confirmed. Review the rejection details below and the node logs.`);
  if (s?.shadow?.diverged) alerts.push('Shadow validation reports a chain divergence from the reference node. Review the validation logs.');
  const text = alerts.join('\n');
  if (host.textContent !== text) host.textContent = text;
  host.hidden = !alerts.length;
  const details = root.querySelector('[data-node-diagnostics]');
  details.hidden = rejection === 'none' && guidance?.destination !== 'diagnostics';
  if (details.hidden) return;
  const historical = rejection === 'historical';
  const onlyHistory = historical && guidance?.destination !== 'diagnostics';
  details.dataset.state = hasActiveNodeIssue(s) ? 'unresolved' : 'info';
  setText('[data-diagnostics-title]', onlyHistory ? 'Past block rejection · chain advanced' : 'Node diagnostics');
  setText('[data-diagnostics-meta]', onlyHistory ? `Height ${num(s.last_block_apply_error.height)} · details` : 'Status, progress & reported issues');
  setText('[data-diagnostic-connection]', state.reachable === false ? 'Unreachable · last reported values' : state.reachable === true ? 'Connected' : 'Unconfirmed');
  setText('[data-diagnostic-chain]', ({ at_tip: 'At chain tip', syncing: 'Syncing', stalled: 'Stalled', disconnected: 'Disconnected' })[s?.sync_state] || s?.sync_state || 'Unavailable');
  setText('[data-diagnostic-headers]', num(s?.best_header_height));
  setText('[data-diagnostic-applied]', num(s?.best_full_block_height));
  setText('[data-diagnostic-peers]', num(s?.peer_count));
  const index = state._slow?.indexerHealth || state._slow?.indexer;
  setText('[data-diagnostic-index]', index ? `${index.status === 'caughtUp' ? 'Ready' : index.status} · ${num(index.indexedHeight)} / ${num(index.fullHeight)} blocks` : 'Unavailable');
  const indexIssues = [];
  if (index?.haltReason) indexIssues.push(`Index halt reason: ${index.haltReason}.`);
  if (index?.repair?.pending) indexIssues.push(`Index repair in progress · ${num(index.repair.nextGi)} boxes processed.`);
  if (index?.repair?.skipped > 0) indexIssues.push(`Index repair skipped ${num(index.repair.skipped)} boxes. Review the indexer logs.`);
  setText('[data-diagnostic-index-issues]', indexIssues.join(' '));
  root.querySelector('[data-diagnostic-index-issues]').hidden = !indexIssues.length;
  const diagnosticIssues = [...alerts];
  if (s?.sync_wedged) diagnosticIssues.push(`Fork below height ${num(s.sync_wedged.fork_below_height)}; rollback window ${num(s.sync_wedged.max_rollback_depth)} blocks.`);
  if (s?.shadow?.diverged) diagnosticIssues.push(`Reference comparison: ${s.shadow.diverged.kind} at height ${num(s.shadow.diverged.height)}.`);
  setText('[data-diagnostic-issues]', diagnosticIssues.join('\n') || (state.reachable === false ? 'Connection unavailable; diagnostic values are from the last response.' : onlyHistory ? 'No active node processing alarm is reported.' : guidance?.detail || 'No additional diagnostic message was returned.'));
  root.querySelector('[data-rejection-details]').hidden = rejection === 'none';
  if (rejection === 'none') return;
  const error = s.last_block_apply_error;
  const age = Number.isFinite(error.age_ms) && error.age_ms >= 0 ? `${dur(Math.floor(error.age_ms / 1000))} ago` : 'Time unavailable';
  const count = s.block_apply_errors_total;
  setText('[data-rejection-meta]', `Height ${num(error.height)} · ${age}${Number.isSafeInteger(count) && count > 0 ? ` · ${num(count)} rejection${count === 1 ? '' : 's'} this session` : ''}`);
  setText('[data-rejection-progress]', historical
    ? `Last reported applied height: ${num(s.best_full_block_height)} — ${num(s.best_full_block_height - error.height)} blocks beyond this rejection. This past event is not an active sync warning.`
    : `Last reported applied height: ${num(s.best_full_block_height)}. Applied blocks have not been confirmed beyond the rejected height.`);
  setText('[data-rejection-id]', error.block_id || 'Unavailable');
  setText('[data-rejection-reason]', error.reason || 'No reason returned. Check the node logs.');
}

function paintSyncSummary(blkH, hdrH, guidance = null) {
  const s = state.status;
  const kind = state.reachable === false ? 'unreachable' : hasActiveNodeIssue(s) ? 'alarm' : s?.bootstrap ? 'bootstrap' : s?.sync_state || 'loading';
  const messages = {
    loading: ['Connecting', 'Waiting for sync status', 'Progress will appear when the node responds.'],
    unreachable: ['Connection lost', 'Your node is unreachable', 'Showing the last received data. Check that the node is running.'],
    disconnected: ['No peers', 'Waiting for network peers', 'The API is reachable, but the node is not connected to peers.'],
    syncing: ['Sync in progress', 'Catching up with the chain', 'Your node is applying historical blocks. Progress is measured against known headers.'],
    at_tip: ['At chain tip', 'Your node is up to date', 'The node reports that its block chain is within sync tolerance.'],
    stalled: ['Needs attention', 'Sync has stopped progressing', 'The node reports a stall. Check peer connectivity and node logs.'],
    bootstrap: ['Snapshot bootstrap', 'Preparing your chain state', 'The node is bootstrapping from a snapshot before normal block sync.'],
    alarm: ['Needs attention', 'Your node reports an issue', 'Review the diagnostic message below. API connectivity does not mean the node is healthy.'],
  };
  const [label, title, copy] = (Object.hasOwn(messages, kind) ? messages[kind] : null) || ['Status', 'Checking chain progress', 'Waiting for a recognized sync state from the node.'];
  root.querySelector('.ov-sync').dataset.syncTone = kind;
  setText('[data-sync-label]', label);
  setText('[data-sync-title]', title);
  const popow = s?.bootstrap?.popow_phase;
  if (state.reachable !== false && kind === 'bootstrap' && popow === 'abandoned') {
    setText('[data-sync-label]', 'NiPoPoW abandoned');
    setText('[data-sync-title]', 'Continuing with ordinary header sync');
    setText('[data-sync-copy]', s.bootstrap.popow_abandon_reason || 'The bootstrap proof could not be applied.');
  } else {
    const idx = state._slow?.indexer;
    const searchCopy = state.identity?.extra_index_enabled === false
      ? 'Block sync is current. Address, box and token searches require the optional search index.'
      : idx?.status === 'syncing'
        ? 'Block sync is current. Address, box and token searches are still indexing.'
        : idx?.status === 'caughtUp'
          ? 'Block sync and chain search are ready.'
          : 'Block sync is current. Search index availability is not yet confirmed.';
    setText('[data-sync-copy]', kind === 'at_tip' ? searchCopy : copy);
  }
  // Guidance shares the status summary. Routine progress needs no second
  // headline or call to action; reported issues keep their concrete next step.
  const needsAction = guidance && (guidance.tone === 'warn' || guidance.tone === 'error' || guidance.destination === 'diagnostics');
  if (needsAction && kind !== 'unreachable') {
    root.querySelector('.ov-sync').dataset.syncTone = guidance.tone === 'error' ? 'alarm' : 'attention';
    setText('[data-sync-label]', 'Needs attention');
    setText('[data-sync-title]', guidance.title);
    setText('[data-sync-copy]', guidance.detail);
  }
  const action = root.querySelector('[data-guidance-action]');
  action.hidden = !needsAction || !guidance.action;
  action.textContent = needsAction ? guidance.action || '' : '';
  action.dataset.destination = needsAction ? guidance.destination || '' : '';
  const pct = blkH != null && hdrH > 0 ? Math.max(0, Math.min(100, blkH / hdrH * 100)) : null;
  // Never round an incomplete chain up to 100%.
  const displayPct = pct == null ? null : Math.floor(pct * 100) / 100;
  setText('[data-sync-percent]', displayPct == null ? '—' : `${displayPct.toFixed(2)}%`);
  setText('[data-sync-target]', num(hdrH));
  setText('[data-sync-remaining]', blkH != null && hdrH != null ? `${num(Math.max(0, hdrH - blkH))} blocks remaining` : 'Waiting for data');
  const progress = root.querySelector('[data-sync-progress]');
  if (displayPct == null) progress.removeAttribute('aria-valuenow');
  else progress.setAttribute('aria-valuenow', String(displayPct));
  root.querySelector('[data-sync-fill]').style.width = `${pct ?? 0}%`;
}

function paintSyncRings() {
  const layers = syncLayers({ ...state, ...state._slow });
  for (const layer of layers) {
    const ring = root.querySelector(`[data-ring="${layer.id}"]`);
    ring.dataset.state = layer.state;
    const unknown = layer.percent == null || layer.state === 'disabled';
    ring.setAttribute('stroke-dasharray', unknown ? '1 3' : `${layer.percent} 100`);
    root.querySelector(`[data-ring-legend="${layer.id}"]`).dataset.state = layer.state;
    setText(`[data-ring-state="${layer.id}"]`, layer.text);
  }
  root.querySelector('[data-sync-rings]').setAttribute('aria-label', layers.map((l) => `${l.label}, ${l.position} ring: ${l.text}`).join('. '));
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
  if (miningOn) state.miningWork = candidate;
  if (candidate?.ok && candidate.data) {
    const work = candidate.data;
    // Track template turnover so the panel can show "refreshed Xs ago" —
    // template_seq bumps whenever the node rebuilds work for the miner.
    const identity = `${work.msg}:${work.template_seq}`;
    if (state.miningSeq !== identity) {
      state.miningSeq = identity;
      state.miningSeqAt = Date.now();
    }
  } else if (miningOn) {
    state.miningSeq = null;
    state.miningSeqAt = null;
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
  rentSource.refresh({ tip: tip?.best_full_block, indexer: indexerHealth, identity: state.identity, reachable: state.reachable })
    .then(() => renderBody());
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
  const t = document.createElement('h2');
  t.className = 'panel__title';
  t.textContent = title;
  head.append(t);
  if (openHash) {
    const a = document.createElement('a');
    a.className = 'ov-open';
    a.href = openHash;
    a.textContent = 'View all ↗';
    head.append(a);
  }
  const body = document.createElement('div');
  body.className = 'panel__body ov-panel__body';
  p.append(head, body);
  return { panel: p, body };
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

function stageRow(label, height, status, tone = 'neutral') {
  const row = document.createElement('tr');
  const name = document.createElement('th');
  name.scope = 'row';
  name.textContent = label;
  const value = document.createElement('td');
  value.className = 'ov-stages__height';
  value.textContent = num(height);
  const detail = document.createElement('td');
  detail.className = 'ov-stages__state';
  detail.dataset.tone = tone;
  detail.textContent = state.reachable === false && height != null ? 'Last known' : status;
  if (state.reachable === false) detail.dataset.tone = 'neutral';
  row.append(name, value, detail);
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

function networkContext() {
  const context = document.createElement('div');
  context.className = 'ov-chain-context ov-network-context';
  const diff = parseDiff(state.tip?.best_header?.difficulty);
  context.append(
    kv('Header difficulty', fmtDiff(diff)),
    kv('Est. network hashrate', diff != null ? fmtHr(deriveHr(diff, state.info)) : '—'),
  );
  return context;
}

function renderBody() {
  if (!root) return;
  const host = root.querySelector('.ov-body');
  if (!host) return;
  // Keyboard-safe rebuild: replacing the subtree while focus is inside it
  // dumps the user's focus to <body> on every 4s tick (the body now holds
  // links — recent blocks, mining reward, event heights). Defer the rebuild
  // to the next tick instead; one stale tick loses to keyboard usability.
  if (host.contains(document.activeElement) || host.querySelector('.ov-block-bar:hover')) return;
  const workDetailsOpen = host.querySelector('.mining-work__details')?.open || false;
  const rentDetailsOpen = host.querySelector('.ov-rent__explanation')?.open || false;
  host.replaceChildren();
  if (viewMode === 'charts') {
    renderCharts(host);
    return;
  }
  const slow = state._slow || {};
  const heading = document.createElement('div');
  heading.className = 'ov-section-heading';
  const headingTitle = document.createElement('h2');
  headingTitle.textContent = 'Inside your node';
  const headingNote = document.createElement('span');
  headingNote.textContent = state.reachable === false ? 'Connection lost · data may be stale' : 'Applied blocks & operational state';
  heading.append(headingTitle, headingNote);
  host.append(heading);
  const grid = document.createElement('div');
  grid.className = 'quad ov-workspace';
  // Independent columns let short operational panels stay compact instead of
  // inheriting the height of the neighboring block/activity lists.
  const operations = document.createElement('div');
  const activity = document.createElement('div');
  operations.className = activity.className = 'ov-column';
  grid.append(operations, activity);

  // Sync
  {
    const { panel: p, body } = panel('Chain stages');
    p.classList.add('ov-pipeline');
    const sync = slow.sync;
    const idx = slow.indexer;
    const hdrH = sync?.best_header_height ?? null;
    const blkH = sync?.best_full_block_height ?? null;
    const blockGap = hdrH > 0 && blkH != null ? Math.max(0, hdrH - blkH) : null;
    const indexTarget = idx?.fullHeight ?? blkH;
    const indexGap = indexTarget != null && idx?.indexedHeight != null ? Math.max(0, indexTarget - idx.indexedHeight) : null;
    const indexHalted = idx?.status === 'halted' || slow.indexerHealth?.status === 'halted';
    const indexReady = idx?.status === 'caughtUp' && !indexHalted;
    const indexStatus = indexHalted ? 'Halted' : indexReady ? 'Ready' : idx?.status === 'syncing' ? (indexGap > 0 ? `${num(indexGap)} behind` : 'Indexing') : state.identity?.extra_index_enabled === false ? 'Disabled' : 'Unavailable';
    const stages = document.createElement('table');
    stages.className = 'ov-stages';
    stages.setAttribute('aria-label', 'Chain stage heights and status');
    stages.innerHTML = '<thead><tr><th scope="col">Stage</th><th scope="col">Height</th><th scope="col">Status</th></tr></thead>';
    const rows = document.createElement('tbody');
    rows.append(
      stageRow('Headers', hdrH, sync?.headers_chain_synced === true ? 'Synced' : sync?.headers_chain_synced === false ? 'Discovering' : 'Unavailable', sync?.headers_chain_synced === true ? 'ok' : 'neutral'),
      stageRow('Blocks', blkH, blockGap == null ? 'Waiting for headers' : blockGap > 0 ? `${num(blockGap)} behind` : 'At headers', blockGap === 0 ? 'ok' : 'neutral'),
      stageRow('Search index', idx?.indexedHeight ?? null, indexStatus, indexHalted ? 'error' : indexReady ? 'ok' : 'neutral'),
    );
    stages.append(rows);
    body.append(stages);
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
      ? `Download queue: ${num(sync.pending_blocks)} blocks · window ${num(sync.download_window)}`
      : 'Download queue unavailable';
    body.append(foot);
    operations.append(p);
  }
  // Chain
  {
    const { panel: p, body } = panel('Recent chain activity', '#explorer');
    p.classList.add('ov-chain-panel');
    body.append(recentChain(slow.recent, state));
    activity.append(p);
  }

  host.append(grid);

  // Operational panels stack independently of chain activity. Mining routes
  // are only queried on mining-enabled nodes; other nodes get a discovery link.
  if (state.identity?.mining) {
    const { panel: p, body } = panel('Mining & network');
    // Middle-ellipsize long ids; short/odd strings render verbatim rather
    // than as duplicated slices.
    const midTrunc = (s, head, tail) => (s && s.length > head + tail + 1 ? `${s.slice(0, head)}…${s.slice(-tail)}` : s || '—');
    body.append(miningWork(state.miningWork, { observedAt: state.miningSeqAt, detailsOpen: workDetailsOpen }));
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
      body.append(miningReward(state.emission, 'local'));
    }
    if (state.minerStats && ownPkHex()) {
      const mine = state.minerStats.miners.find((mm) => mm.pk === ownPkHex());
      body.append(
        kv(`your blocks · last ${num(state.minerStats.blocks)}`, String(mine?.count || 0), 'var(--tx2)'),
      );
    }
    body.append(networkContext(), miningSectionFoot());
    operations.append(p);
  } else if (state.identity && !state.identity.mining) {
    // Non-mining node: a one-line stub instead of hiding the panel — the
    // Mining section (network landscape) is still worth discovering. No
    // mining fetches happen in this state (see the miningOn gates above).
    const { panel: p, body } = panel('Mining & network');
    body.append(kv('mining', 'disabled', 'var(--tx3)'));
    body.append(networkContext(), miningSectionFoot());
    operations.append(p);
  }

  // Block activity lives in the chain panel. Keep other retained events
  // separate so a stream of blocks cannot bury peer, index and reorg details.
  host.append(rentForecastView(rentSource.get(), rentDetailsOpen));
  {
    const { panel: p, body } = panel('Node events');
    p.classList.add('ov-event-panel');
    body.append(nodeEvents(slow.events, state));
    host.append(p);
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
    item('Memory · RSS', bytes(h?.rss_bytes)),
    item('disk free', bytes(h?.disk_free_bytes)),
    item('Chain database', bytes(h?.state_db_bytes)),
    item('Index database', bytes(h?.index_db_bytes)),
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
  const t = document.createElement('h2');
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
