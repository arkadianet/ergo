// Dashboard bootstrap: wires the router, settings, status line, and
// section-gated polling (fast status always; slow data only for the visible
// section and only while the tab is visible).
//
// Section lifecycle (all hooks except mount are optional):
//   mount(el)   — build the section's DOM once (called lazily on first show).
//   onShow()    — section became active (start section-specific work / refresh).
//   onHide()    — section left (stop work; scrub sensitive state — see wallet).
//   onFast(d)   — 1 Hz tick with {status, info}, only while active.
//   onSlow()    — 4 s tick (may be async); only while active. Serialized
//                 per-section so a slow fetch never overlaps its next tick.
//   isBusy()    — section holds in-flight user input; it patches read-only
//                 cells instead of rebuilding (the section enforces this).
//   canLeave()  — return false to veto navigation (wallet mnemonic gate).
//   onRoute(t)  — the hash sub-path after `#section/` changed (deep links,
//                 e.g. `#explorer/tx/<id>`); also fired on section entry with
//                 the current tail. Sections without sub-routes never see it.
import { startRouter } from './router.js';
import { initSettings, applyPrefs } from './settings.js';
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
const INFO_REFRESH_MS = 30_000;
let cachedInfo = null;
let lastInfoAt = 0;
// Holds the section name whose onSlow() is in flight, so a 4 s tick can't
// overlap a still-running slow fetch for the same section; a navigation to a
// different section is not blocked (the names differ).
let slowInFlight = null;

function setConn(ok) {
  const dot = document.getElementById('conn-dot');
  const state = document.getElementById('conn-state');
  if (dot) {
    dot.style.color = ok ? 'var(--green)' : 'var(--red)';
    // The CSS heartbeat only runs while live — a pulsing "Unreachable" dot
    // would read as activity where there is none.
    dot.classList.toggle('is-live', ok);
  }
  if (state) state.textContent = ok ? 'Live' : 'Unreachable';
}

function tickClock() {
  const el = document.getElementById('clock');
  if (el) el.textContent = new Date().toLocaleTimeString();
}

async function fast() {
  if (document.visibilityState === 'hidden') return;
  const now = Date.now();
  const needInfo = !cachedInfo || now - lastInfoAt >= INFO_REFRESH_MS;
  const [status, info] = await Promise.all([api.status(), needInfo ? api.info() : Promise.resolve(cachedInfo)]);
  if (needInfo) {
    lastInfoAt = now;
    if (info) cachedInfo = info;
  }
  setConn(!!status);
  const net = document.getElementById('side-net');
  const infoForRender = cachedInfo || info;
  if (net && infoForRender) net.textContent = `${infoForRender.network ?? ''} · v${infoForRender.version ?? ''}`;
  const r = current && renderers[current];
  if (r && r.onFast) r.onFast({ status, info: infoForRender });
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
  if (current === s) {
    // Same section, new sub-path (deep-link navigation within the section).
    if (r && r.onRoute) r.onRoute(tail || '');
    return;
  }
  const prev = current && renderers[current];
  if (prev && prev.onHide) prev.onHide();
  current = s;
  if (!mounted.has(s)) {
    r.mount(document.getElementById(`section-${s}`));
    mounted.add(s);
  }
  if (r.onShow) r.onShow();
  if (r.onRoute) r.onRoute(tail || '');
  slow(); // immediate first paint for the entered section
}

// Asked by the router before leaving `prev`; a section may veto (return false).
function beforeLeave(prev) {
  const r = renderers[prev];
  return !r || !r.canLeave || r.canLeave();
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
  startRouter(SECTIONS, show, beforeLeave);
  // "/" from anywhere jumps to the explorer omnibox (GitHub-style). Ignored
  // while typing in a field or while a dialog is open, so it never swallows a
  // literal slash the user is entering.
  document.addEventListener('keydown', (e) => {
    if (e.key !== '/' || e.ctrlKey || e.metaKey || e.altKey) return;
    const t = e.target;
    if (t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.isContentEditable)) return;
    if (document.querySelector('dialog[open]')) return;
    // Never initiate navigation away from a busy section: on the wallet
    // mnemonic gate, '/' would raise the leave-confirm where Enter (the
    // default OK) discards the recovery phrase — a two-keystroke slip.
    const r = renderers[current];
    if (r && r.isBusy && r.isBusy()) return;
    e.preventDefault();
    if (current !== 'explorer') location.hash = 'explorer';
    // Focus after the router has painted the section (hashchange is async).
    setTimeout(() => explorer.focusSearch(), 0);
  });
  fast();
  setInterval(fast, 1000);
  setInterval(slow, 4000);
  setInterval(tickClock, 1000);
  tickClock();
}

boot();
