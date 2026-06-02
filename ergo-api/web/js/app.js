// Dashboard bootstrap: wires the router, settings, status line, and
// section-gated polling (fast status always; slow data only for the
// visible section and only while the tab is visible).
import { startRouter } from './router.js';
import { initSettings, applyPrefs } from './settings.js';
import { api } from './api-client.js';
import * as overview from './overview.js';
import * as peers from './peers.js';
import * as mempool from './mempool.js';

const SECTIONS = ['overview', 'peers', 'mempool'];
const renderers = { overview, peers, mempool };
let current = 'overview';

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
  if (renderers[current].onFast) renderers[current].onFast({ status, info });
}

async function slow() {
  if (document.visibilityState === 'hidden') return;
  if (renderers[current].onSlow) await renderers[current].onSlow();
}

function boot() {
  initSettings(
    document.getElementById('settings-dialog'),
    document.getElementById('open-settings'),
  );
  applyPrefs();
  startRouter(SECTIONS, (s) => {
    current = s;
    renderers[s].mount(document.getElementById(`section-${s}`));
    slow();
  });
  fast();
  slow();
  setInterval(fast, 1000);
  setInterval(slow, 4000);
  setInterval(tickClock, 1000);
  tickClock();
}

boot();
