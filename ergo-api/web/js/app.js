// Dashboard bootstrap: wires the router, settings, status line, and
// section-gated polling (status heartbeat; slow data only for the visible
// section and only while the tab is visible). Tip / mempool / peers panels
// prefer WS; HTTP remains the fallback.
//
// Section lifecycle (all hooks except mount are optional):
//   mount(el)   — build the section's DOM once (called lazily on first show).
//   onShow()    — section became active (start section-specific work / refresh).
//   onHide()    — section left (stop work; scrub sensitive state — see wallet).
//   onFast(d)   — status tick with {status, info}, only while active.
//   onSlow()    — slow tick (may be async); only while active. Serialized
//                 per-section so a slow fetch never overlaps its next tick.
//   isBusy()    — section holds in-flight user input; it patches read-only
//                 cells instead of rebuilding (the section enforces this).
//   canLeave()  — return false to veto navigation (wallet mnemonic gate).
//   onRoute(t)  — the hash sub-path after `#section/` changed (deep links,
//                 e.g. `#explorer/tx/<id>`); also fired on section entry with
//                 the current tail. Sections without sub-routes never see it.
import { startRouter } from './router.js';
import { initSettings, applyPrefs } from './settings.js';
import { initWorkspaceSearch } from './workspace-search.js';
import { initAuth } from './auth.js';
import { api } from './api-client.js';
import * as overview from './overview.js';
import * as explorer from './explorer.js';
import * as peers from './peers.js';
import * as mempool from './mempool.js';
import * as mining from './mining.js';
import * as voting from './voting.js';
import * as wallet from './wallet.js';

const SECTIONS = ['overview', 'explorer', 'peers', 'mempool', 'mining', 'voting', 'wallet'];
const renderers = { overview, explorer, peers, mempool, mining, voting, wallet };
const mounted = new Set();
let current = null;
// Tip/mempool/peers come from WS; /info is rarely needed for the chrome.
const INFO_REFRESH_MS = 30_000;
// Status heartbeat for conn-dot / peer+mempool counts (not tip or uptime).
const STATUS_REFRESH_MS = 5_000;
const SLOW_REFRESH_MS = 4_000;
let cachedInfo = null;
let lastInfoAt = 0;
// Holds the section name whose onSlow() is in flight, so a 4 s tick can't
// overlap a still-running slow fetch for the same section; a navigation to a
// different section is not blocked (the names differ).
let slowInFlight = null;
let fastInFlight = false;
let lastStatusAt = 0;
let pendingChainQuery = null;

function setConn(ok) {
  const dot = document.getElementById('conn-dot');
  const state = document.getElementById('conn-state');
  if (dot) {
    dot.style.color = ok ? 'var(--green)' : 'var(--red)';
    // The CSS heartbeat only runs while live — a pulsing "Unreachable" dot
    // would read as activity where there is none.
    dot.classList.toggle('is-live', ok);
  }
  if (ok) lastStatusAt = Date.now();
  if (state) state.textContent = ok ? 'API connected' : 'API unreachable';
  const banner = document.getElementById('connection-banner');
  if (banner) banner.hidden = ok;
  tickClock();
}

function tickClock() {
  const el = document.getElementById('clock');
  if (el) el.textContent = lastStatusAt
    ? `Updated ${Math.max(0, Math.floor((Date.now() - lastStatusAt) / 1000))}s ago`
    : 'Waiting for first response';
}

async function fast() {
  if (document.visibilityState === 'hidden') return;
  if (fastInFlight) return;
  fastInFlight = true;
  try {
    const now = Date.now();
    const needInfo = !cachedInfo || now - lastInfoAt >= INFO_REFRESH_MS;
    let status = null;
    let info = cachedInfo;
    try {
      [status, info] = await Promise.all([
        api.status(),
        needInfo ? api.info() : Promise.resolve(cachedInfo),
      ]);
    } catch {
      // getJson normally resolves null; keep cached info and mark unreachable.
      setConn(false);
      renderers[current]?.onFast?.({ status: null, info: cachedInfo, reachable: false });
      return;
    }
    if (needInfo) {
      lastInfoAt = now;
      if (info) cachedInfo = info;
    }
    setConn(!!status);
    const net = document.getElementById('side-net');
    const infoForRender = cachedInfo || info;
    if (net && infoForRender) net.textContent = `${infoForRender.network ?? ''} · v${infoForRender.version ?? ''}`;
    const r = current && renderers[current];
    if (r && r.onFast) r.onFast({ status, info: infoForRender, reachable: !!status });
  } finally {
    fastInFlight = false;
  }
}

async function slow() {
  if (document.visibilityState === 'hidden') return;
  const sec = current;
  const r = sec && renderers[sec];
  if (!r || !r.onSlow) return;
  if (slowInFlight === sec) return; // same section already refreshing
  slowInFlight = sec;
  try {
    await r.onSlow();
  } finally {
    if (slowInFlight === sec) slowInFlight = null;
  }
}

function show(s, tail) {
  const r = renderers[s];
  const pageName = s.charAt(0).toUpperCase() + s.slice(1);
  document.getElementById('workspace-page').textContent = pageName;
  document.title = `${pageName} · Ergo Node`;
  if (current === s) {
    // Same section, new sub-path (deep-link navigation within the section).
    if (r && r.onRoute) r.onRoute(tail || '');
    return;
  }
  const prev = current && renderers[current];
  if (prev && prev.onHide) prev.onHide();
  current = s;
  const side = document.querySelector('.side');
  const navToggle = document.getElementById('nav-toggle');
  if (side && navToggle) {
    // A selected mobile link will be hidden; move focus back to the menu.
    if (side.classList.contains('side--open') && matchMedia('(max-width: 760px)').matches && side.contains(document.activeElement)) navToggle.focus();
    side.classList.remove('side--open');
    navToggle.setAttribute('aria-expanded', 'false');
  }
  if (!mounted.has(s)) {
    r.mount(document.getElementById(`section-${s}`));
    mounted.add(s);
  }
  if (r.onShow) r.onShow();
  if (r.onRoute) r.onRoute(tail || '');
  if (s === 'explorer' && pendingChainQuery != null) {
    const query = pendingChainQuery;
    pendingChainQuery = null;
    explorer.searchQuery(query);
  }
  window.scrollTo({ top: 0, behavior: 'instant' });
  slow(); // immediate first paint for the entered section
  fast(); // don't show an old status when switching sections
}

// Asked by the router before leaving `prev`; a section may veto (return false).
function beforeLeave(prev) {
  const r = renderers[prev];
  const allowed = !r || !r.canLeave || r.canLeave();
  if (!allowed) pendingChainQuery = null;
  return allowed;
}

function boot() {
  initSettings(
    document.getElementById('settings-dialog'),
    document.getElementById('open-settings'),
  );
  initAuth(
    document.getElementById('auth-chip'),
    document.getElementById('auth-dialog'),
  );
  applyPrefs();
  document.querySelector('.skip-link')?.addEventListener('click', (event) => {
    event.preventDefault();
    document.getElementById('main-content').focus();
    document.getElementById('main-content').scrollIntoView({ block: 'start' });
  });
  const navToggle = document.getElementById('nav-toggle');
  navToggle?.addEventListener('click', () => {
    const expanded = document.querySelector('.side').classList.toggle('side--open');
    navToggle.setAttribute('aria-expanded', String(expanded));
  });
  const search = initWorkspaceSearch({
    trigger: document.getElementById('global-search'),
    canOpen: () => !renderers[current]?.isBusy?.() && !document.querySelector('dialog[open]'),
    navigate: section => { location.hash = section; },
    search: query => {
      if (current === 'explorer') explorer.searchQuery(query);
      else { pendingChainQuery = query; location.hash = 'explorer'; }
    },
  });
  startRouter(SECTIONS, show, beforeLeave);
  // "/" opens workspace search without leaving the page. Ignored
  // while typing in a field or while a dialog is open, so it never swallows a
  // literal slash the user is entering.
  document.addEventListener('keydown', (e) => {
    const command = (e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k' && !e.altKey;
    if (!command && (e.key !== '/' || e.ctrlKey || e.metaKey || e.altKey)) return;
    const t = e.target;
    if (!command && t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.tagName === 'SELECT' || t.isContentEditable)) return;
    if (document.querySelector('dialog[open]')) return;
    // Never initiate navigation away from a busy section: on the wallet
    // mnemonic gate, '/' would raise the leave-confirm where Enter (the
    // default OK) discards the recovery phrase — a two-keystroke slip.
    const r = renderers[current];
    if (r && r.isBusy && r.isBusy()) return;
    e.preventDefault();
    search();
  });
  fast();
  setInterval(fast, STATUS_REFRESH_MS);
  setInterval(slow, SLOW_REFRESH_MS);
  setInterval(tickClock, 1000);
  tickClock();
}

boot();
