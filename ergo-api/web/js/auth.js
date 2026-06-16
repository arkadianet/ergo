// Single source of truth for the operator api_key and its verification state.
//
// The key lives in this tab's sessionStorage (never disk) and is sent as the
// `api_key` request header by api-client.js (and the wallet section). It is
// NOT the wallet password — that unlocks the wallet server-side and stays in
// the wallet flow.
//
// Verification: `GET /wallet/status` is always mounted and api_key-gated, so it
// is a universal probe — 200 => valid, 403 => invalid — regardless of whether a
// wallet is configured. Other gated calls confirm/deny opportunistically via
// report(). Public reads return 200 even with a bad key, so a 200 from them is
// NOT treated as proof; only 403 (a definitive reject) or a 2xx from a *gated*
// call flips the state.
const KEY = 'ergo.apikey';
const LEGACY = 'ergo_api_key'; // pre-unification wallet slot

// One-time migration: MOVE a legacy wallet key into the unified slot, then
// remove the legacy slot so clearing the key can never resurrect the old value.
(function migrateLegacyKey() {
  try {
    const legacy = sessionStorage.getItem(LEGACY);
    if (legacy) {
      if (!sessionStorage.getItem(KEY)) sessionStorage.setItem(KEY, legacy);
      sessionStorage.removeItem(LEGACY);
    }
  } catch {
    /* sessionStorage blocked — nothing to migrate */
  }
})();

// none: no key set · checking: probe in flight · authorized: probe 200 ·
// invalid: probe/gated-call 403 · unverified: key set but probe inconclusive.
let state = 'none';
const subs = new Set();

export function getApiKey() {
  try {
    return sessionStorage.getItem(KEY) || '';
  } catch {
    return '';
  }
}

// Reported state collapses to 'none' whenever no key is set, so subscribers
// never see a stale 'authorized' after a clear.
export function authState() {
  return getApiKey() ? state : 'none';
}

export function subscribe(fn) {
  subs.add(fn);
  fn(authState());
  return () => subs.delete(fn);
}

function setState(s) {
  if (s === state) return;
  state = s;
  const snap = authState();
  for (const fn of subs) fn(snap);
}

// Opportunistic re-verify from api-client / wallet calls. `gated` marks a call
// the server actually auth-checks; a 2xx there confirms the key, whereas a 2xx
// from a public endpoint proves nothing. A 403 anywhere is a definitive reject.
// `keyUsed` is the api_key the request was sent with; a response that arrives
// after the operator changed the key is ignored so it can't mislabel the new
// key (e.g. key A's 403 marking key B invalid).
export function report(status, gated = false, keyUsed) {
  const key = getApiKey();
  if (!key) return;
  if (keyUsed !== undefined && keyUsed !== key) return;
  if (status === 403) setState('invalid');
  else if (gated && status >= 200 && status < 300 && state !== 'authorized') {
    setState('authorized');
  }
}

async function verify() {
  const probeKey = getApiKey();
  if (!probeKey) {
    setState('none');
    return;
  }
  setState('checking');
  try {
    const r = await fetch('/wallet/status', {
      cache: 'no-store',
      headers: { api_key: probeKey },
    });
    if (probeKey !== getApiKey()) return; // a newer setApiKey superseded this probe
    if (r.status === 200) setState('authorized');
    else if (r.status === 403) setState('invalid');
    else setState('unverified');
  } catch {
    if (probeKey === getApiKey()) setState('unverified');
  }
}

export async function setApiKey(v) {
  const key = (v || '').trim();
  try {
    if (key) sessionStorage.setItem(KEY, key);
    else sessionStorage.removeItem(KEY);
    sessionStorage.removeItem(LEGACY);
  } catch {
    /* ignore storage errors */
  }
  if (key) await verify();
  else setState('none');
}

const LABELS = {
  none: 'Authorize',
  checking: 'Checking…',
  authorized: 'Authorized',
  invalid: 'Invalid key',
  unverified: 'Key set',
};
const DOT = {
  none: 'var(--tx3)',
  checking: 'var(--yellow)',
  authorized: 'var(--green)',
  invalid: 'var(--red)',
  unverified: 'var(--blue)',
};
const TITLES = {
  none: 'No api_key set — click to authorize operator actions',
  checking: 'Verifying the api_key…',
  authorized: 'api_key verified — operator actions enabled',
  invalid: 'api_key rejected (403) — click to re-enter',
  unverified: 'api_key set but unverified (status probe unreachable)',
};

function renderChip(chip, s) {
  const dot = document.createElement('span');
  dot.textContent = '●';
  dot.style.color = DOT[s];
  dot.setAttribute('aria-hidden', 'true');
  const label = document.createElement('span');
  label.textContent = ` ${LABELS[s]}`;
  chip.replaceChildren(dot, label);
  chip.setAttribute('aria-label', `Authorization: ${LABELS[s]}`);
  chip.title = TITLES[s];
}

// Set by initAuth so other surfaces (the Overview prompt, voting hint) can open
// the Authorize dialog without reaching into the DOM themselves.
let dialogEl = null;
let inputEl = null;

// Open the Authorize dialog (prefilled with the current key, if any).
export function promptAuthorize() {
  if (!dialogEl) return;
  inputEl.value = getApiKey();
  dialogEl.showModal();
}

// Wire the shell lock chip + its dialog. The dialog template is static (no
// untrusted interpolation); the field value is assigned via the DOM.
export function initAuth(chip, dialog) {
  dialog.innerHTML = `
    <form method="dialog" class="dialog__body">
      <h3 class="micro-label">Authorize</h3>
      <p class="dialog__note">The operator <code>api_key</code> authorizes write
        actions (voting, wallet). It is held only in this tab
        (<code>sessionStorage</code>), sent as the <code>api_key</code> request
        header — never written to disk. This is not the wallet password.</p>
      <label>api_key
        <input id="auth-key" class="input" type="password" autocomplete="off"
               spellcheck="false"></label>
      <div class="dialog__actions">
        <button class="btn btn--primary" value="save" type="submit">Save</button>
        <button class="btn btn--danger" value="clear" type="submit">Clear</button>
        <button class="btn" value="cancel" type="submit">Close</button>
      </div>
    </form>`;
  const input = dialog.querySelector('#auth-key');
  dialogEl = dialog;
  inputEl = input;
  chip.addEventListener('click', promptAuthorize);
  dialog.addEventListener('close', () => {
    const v = dialog.returnValue;
    if (v === 'save') setApiKey(input.value);
    else if (v === 'clear') setApiKey('');
    input.value = ''; // don't leave the key in the DOM after the dialog closes
  });
  subscribe((s) => renderChip(chip, s));
  if (getApiKey()) verify(); // probe a key restored from a prior load / migration
}
