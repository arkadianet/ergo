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
import { startRouter } from './router.js';
import { initSettings, applyPrefs } from './settings.js';
import { api } from './api-client.js';
import * as overview from './overview.js';
import * as peers from './peers.js';
import * as mempool from './mempool.js';
import * as voting from './voting.js';

const SECTIONS = ['overview', 'peers', 'mempool', 'voting'];
const renderers = { overview, peers, mempool, voting };
const mounted = new Set();
let current = null;
// Holds the section name whose onSlow() is in flight, so a 4 s tick can't
// overlap a still-running slow fetch for the same section; a navigation to a
// different section is not blocked (the names differ).
let slowInFlight = null;

function setConn(ok) {
  const dot = document.getElementById('conn-dot');
  const state = document.getElementById('conn-state');
  if (dot) dot.style.color = ok ? 'var(--green)' : 'var(--red)';
  if (state) state.textContent = ok ? 'live' : 'unreachable';
}

function tickClock() {
  const el = document.getElementById('clock');
  if (el) el.textContent = new Date().toLocaleTimeString();
}

async function fast() {
  if (document.visibilityState === 'hidden') return;
  const [status, info] = await Promise.all([api.status(), api.info()]);
  setConn(!!status);
  const net = document.getElementById('side-net');
  if (net && info) net.textContent = `${info.network ?? ''} · v${info.version ?? ''}`;
  const r = current && renderers[current];
  if (r && r.onFast) r.onFast({ status, info });
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

function show(s) {
  if (current === s) return;
  const prev = current && renderers[current];
  if (prev && prev.onHide) prev.onHide();
  current = s;
  const r = renderers[s];
  if (!mounted.has(s)) {
    r.mount(document.getElementById(`section-${s}`));
    mounted.add(s);
  }
  if (r.onShow) r.onShow();
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
  applyPrefs();
  startRouter(SECTIONS, show, beforeLeave);
  fast();
  setInterval(fast, 1000);
  setInterval(slow, 4000);
  setInterval(tickClock, 1000);
  tickClock();
}

boot();
