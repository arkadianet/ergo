// Wallet section — a thin remote control for the node's /wallet/* REST API,
// folded into the dashboard SPA. The browser never holds the master key, never
// derives, never signs: every operation is an api_key-authenticated call (the
// key lives in the shell Authorize chip, auth.js) to a /wallet/* route. The
// wallet PASSWORD (unlock) is a separate secret entered here and POSTed, never
// stored.
//
// Two layered gates: (1) the shell api_key (auth.js) — no key => an Authorize
// prompt; (2) the server-side wallet unlock — locked => an unlock form. Secrets
// on screen (mnemonic, passwords, send draft) are scrubbed on section exit
// (onHide) since, unlike the old standalone page, navigating away no longer
// unloads the document. Server-supplied strings are written via textContent
// only — never innerHTML.
import { api } from './api-client.js';
import { subscribe, promptAuthorize } from './auth.js';
import { erg, num, truncMiddle, nanoErgFromDecimal } from './format.js';

let root = null;
let authUnsub = null;
// True while a recovery phrase is on screen (init flow): polling is suspended
// and navigation is guarded so a background refresh / accidental nav can't
// destroy the only copy.
let mnemonicGateOpen = false;
// True while an init/restore/unlock/send POST is in flight.
let submitInFlight = false;
// Panes are built once and visibility-toggled so a refresh never wipes input;
// these flags also gate the rebuild and are reset by scrubSecrets().
let onboardRendered = false;
let sendRendered = false;
let keysRendered = false;
let unlockRendered = false;

const MAX_SAFE = BigInt(Number.MAX_SAFE_INTEGER);
const EXT_WARNING =
  'Any browser extension with access to this page can read the mnemonic while ' +
  'it is on screen. Prefer a clean browser profile; never reuse a mnemonic ' +
  'from another wallet.';

const q = (sel) => root && root.querySelector(sel);

// el("button", {class:"btn", text:"Lock", onclick:fn}, ...children).
// `text` sets textContent; `on*` keys bind listeners; everything else is a
// plain attribute. No `html` branch by design.
function el(tag, props, ...kids) {
  const n = document.createElement(tag);
  if (props) {
    for (const k of Object.keys(props)) {
      const v = props[k];
      if (k === 'class') n.className = v;
      else if (k === 'text') n.textContent = v;
      else if (k.startsWith('on') && typeof v === 'function') n.addEventListener(k.slice(2), v);
      else if (v !== false && v != null) n.setAttribute(k, v === true ? '' : v);
    }
  }
  for (const kid of kids) if (kid != null) n.append(kid);
  return n;
}

function field(labelText, control) {
  return el('label', { class: 'w-field' }, el('span', { class: 'w-label', text: labelText }), control);
}

// ── lifecycle ──────────────────────────────────────────────────────────────
export function mount(el_) {
  root = el_;
  // Static shells only; bodies are filled with DOM nodes (textContent) below.
  root.innerHTML = `
    <div class="pg-head"><span class="pg-title">Wallet</span></div>
    <div class="ov-prompt banner banner--info" data-wallet-prompt hidden></div>
    <div class="w-wrap" data-wallet-app hidden>
      <div class="banner banner--warn" data-scan-banner hidden></div>
      <section class="panel" data-onboard-panel hidden>
        <div class="panel__head"><div class="panel__title"><span class="panel__dot panel__dot--orange"></span>Set up wallet</div></div>
        <div class="panel__body" data-onboard-body></div>
      </section>
      <section class="panel" data-status-panel>
        <div class="panel__head"><div class="panel__title"><span class="panel__dot" data-status-dot></span>Wallet status</div><div class="panel__right" data-status-right></div></div>
        <div class="panel__body" data-status-body></div>
      </section>
      <section class="panel" data-balances-panel>
        <div class="panel__head"><div class="panel__title"><span class="panel__dot panel__dot--blue"></span>Balances</div><div class="panel__right" data-balances-right></div></div>
        <div class="panel__body" data-balances-body></div>
      </section>
      <section class="panel" data-addresses-panel>
        <div class="panel__head"><div class="panel__title"><span class="panel__dot panel__dot--green"></span>Addresses</div><div class="panel__right" data-addresses-right></div></div>
        <div class="panel__body" data-addresses-body></div>
      </section>
      <section class="panel" data-send-panel hidden>
        <div class="panel__head"><div class="panel__title"><span class="panel__dot panel__dot--orange"></span>Send payment</div></div>
        <div class="panel__body" data-send-body></div>
      </section>
      <section class="panel" data-keys-panel hidden>
        <div class="panel__head"><div class="panel__title"><span class="panel__dot panel__dot--green"></span>Keys</div></div>
        <div class="panel__body" data-keys-body></div>
      </section>
    </div>`;
  const prompt = q('[data-wallet-prompt]');
  prompt.append(
    el('span', { text: 'Authorize with the operator api_key to use the wallet.' }),
    el('button', { class: 'btn btn--primary btn--sm', type: 'button', text: 'Authorize', onclick: promptAuthorize }),
  );
}

export function onShow() {
  // subscribe() fires immediately with the current auth state, gating the view.
  authUnsub = subscribe(renderAuthGate);
}

export function onHide() {
  if (authUnsub) {
    authUnsub();
    authUnsub = null;
  }
  scrubSecrets();
}

// Skip the 4 s poll while a recovery phrase is shown or a submit is in flight,
// so a refresh can't navigate away from the mnemonic gate or fight a request.
export function isBusy() {
  return mnemonicGateOpen || submitInFlight;
}

export function onSlow() {
  if (isBusy()) return;
  if (!q('[data-wallet-app]') || q('[data-wallet-app]').hidden) return;
  return refresh();
}

// Veto navigation while the once-shown recovery phrase is still on screen.
export function canLeave() {
  if (!mnemonicGateOpen) return true;
  return window.confirm(
    'Your recovery phrase is on screen and has not been confirmed saved. ' +
      'Leaving discards it permanently. Leave anyway?',
  );
}

// ── auth gate + secret scrub ─────────────────────────────────────────────────
function renderAuthGate(s) {
  if (!root) return;
  const blocked = s === 'none' || s === 'invalid';
  q('[data-wallet-prompt]').hidden = !blocked;
  q('[data-wallet-app]').hidden = blocked;
  if (blocked) {
    scrubSecrets();
  } else {
    refresh();
  }
}

function scrubSecrets() {
  if (!root) return;
  for (const inp of root.querySelectorAll('input[type="password"]')) inp.value = '';
  const pre = q('[data-mnemonic]');
  if (pre) pre.textContent = '';
  mnemonicGateOpen = false;
  onboardRendered = sendRendered = keysRendered = unlockRendered = false;
  // Drop memoised panes so a re-entry rebuilds them fresh (no lingering
  // password / mnemonic / send draft in a detached-but-retained input).
  for (const sel of ['[data-onboard-body]', '[data-send-body]', '[data-keys-body]']) {
    const b = q(sel);
    if (b) b.replaceChildren();
  }
}

// ── status panel ─────────────────────────────────────────────────────────────
function kvRows(rows) {
  const kv = el('div', { class: 'kv' });
  for (const [label, value, cls] of rows) {
    kv.append(el('div', { class: 'k', text: label }), el('div', { class: `v ${cls || ''}`, text: value }));
  }
  return kv;
}

function renderStatusPanel(s) {
  const dot = q('[data-status-dot]');
  dot.className = 'panel__dot ' + (s.isUnlocked ? 'panel__dot--green' : s.isInitialized ? 'panel__dot--orange' : '');
  const body = q('[data-status-body]');
  const right = q('[data-status-right]');
  right.replaceChildren();

  let kvWrap = q('[data-status-kv]');
  if (!kvWrap) {
    body.replaceChildren();
    kvWrap = el('div', { 'data-status-kv': true });
    body.append(kvWrap);
  }

  const changeAddr = el('div', { class: 'v v--hash', text: truncMiddle(s.changeAddress || '', 10, 8) || '—' });
  if (s.changeAddress) changeAddr.title = s.changeAddress;
  const kv = el('div', { class: 'kv' });
  kv.append(
    el('div', { class: 'k', text: 'initialized' }),
    el('div', { class: `v ${s.isInitialized ? 'v--green' : 'v--dim'}`, text: String(s.isInitialized) }),
    el('div', { class: 'k', text: 'unlocked' }),
    el('div', { class: `v ${s.isUnlocked ? 'v--green' : 'v--dim'}`, text: String(s.isUnlocked) }),
    el('div', { class: 'k', text: 'change address' }),
    changeAddr,
    el('div', { class: 'k', text: 'wallet height' }),
    el('div', { class: 'v', text: num(s.walletHeight) }),
  );
  if (s.error) kv.append(el('div', { class: 'k', text: 'error' }), el('div', { class: 'v v--red', text: s.error }));
  kvWrap.replaceChildren(kv);

  if (s.isUnlocked) {
    const uw = q('[data-unlock-wrap]');
    if (uw) uw.remove();
    unlockRendered = false;
    right.append(el('button', { class: 'btn btn--danger btn--sm', text: 'Lock', onclick: lockWallet }));
  } else if (!unlockRendered) {
    const old = q('[data-unlock-wrap]');
    if (old) old.remove();
    body.append(el('div', { 'data-unlock-wrap': true }, renderUnlockForm()));
    unlockRendered = true;
  }
}

function renderUnlockForm() {
  const input = el('input', { type: 'password', class: 'input', placeholder: 'wallet password', autocomplete: 'off', spellcheck: 'false' });
  const btn = el('button', { class: 'btn btn--primary', type: 'submit', text: 'Unlock' });
  const err = el('div', { class: 'banner banner--err', hidden: true });
  const form = el(
    'form',
    {
      class: 'w-row',
      onsubmit: async (ev) => {
        ev.preventDefault();
        err.hidden = true;
        btn.disabled = true;
        submitInFlight = true;
        const res = await api.wallet.unlock(input.value);
        submitInFlight = false;
        btn.disabled = false;
        if (res.status === 403) return;
        if (res.ok) {
          input.value = '';
          refresh();
        } else {
          err.textContent = res.reason || `unlock failed (${res.status})`;
          err.hidden = false;
        }
      },
    },
    input,
    btn,
  );
  return el('div', null, form, err);
}

async function lockWallet() {
  const res = await api.wallet.lock();
  if (res.status === 403) return;
  if (!res.ok) {
    // Surface a failed lock instead of silently refreshing as if it worked.
    q('[data-status-right]').replaceChildren(el('span', { class: 'banner banner--err', text: res.reason || `lock failed (${res.status})` }));
    return;
  }
  refresh();
}

// ── scan-invalidated banner ──────────────────────────────────────────────────
function renderScanBanner(s) {
  const b = q('[data-scan-banner]');
  if (s.error === 'scan_invalidated') {
    b.textContent =
      'Wallet scan invalidated — balances and addresses may be stale until a rescan. ' +
      'Trigger one from the CLI/API (POST /wallet/rescan).';
    b.hidden = false;
  } else {
    b.hidden = true;
  }
}

// ── reads: balances + addresses ──────────────────────────────────────────────
function lockedNotes() {
  q('[data-balances-body]').replaceChildren(el('div', { class: 'muted', text: 'Unlock the wallet to view balances.' }));
  q('[data-addresses-body]').replaceChildren(el('div', { class: 'muted', text: 'Unlock the wallet to view addresses.' }));
  q('[data-balances-right]').textContent = '';
  q('[data-addresses-right]').textContent = '';
  q('[data-keys-panel]').hidden = true;
}

async function refreshBalances() {
  const res = await api.wallet.balances();
  if (res.status === 403) return;
  const body = q('[data-balances-body]');
  const right = q('[data-balances-right]');
  if (!res.ok) {
    right.textContent = '';
    body.replaceChildren(el('div', { class: 'muted', text: res.reason || `balances unavailable (${res.status})` }));
    return;
  }
  const b = res.data;
  right.textContent = `height ${num(b.height)}`;
  body.replaceChildren(kvRows([['confirmed', `${erg(b.balance)} ERG`, 'v--green']]));
  const assets = b.assets || [];
  if (assets.length) {
    const tokKv = el('div', { class: 'kv' });
    for (const a of assets) {
      const id = el('div', { class: 'k v--hash', text: truncMiddle(a.tokenId, 10, 8) });
      id.title = a.tokenId;
      tokKv.append(id, el('div', { class: 'v', text: num(a.amount) }));
    }
    body.append(el('div', { class: 'muted', text: `tokens (${assets.length})` }), tokKv);
  } else {
    body.append(el('div', { class: 'muted', text: 'no tokens' }));
  }
}

async function refreshAddresses() {
  const res = await api.wallet.addresses();
  if (res.status === 403) return;
  const body = q('[data-addresses-body]');
  const right = q('[data-addresses-right]');
  if (!res.ok) {
    right.textContent = '';
    body.replaceChildren(el('div', { class: 'muted', text: res.reason || `addresses unavailable (${res.status})` }));
    return;
  }
  const list = res.data || [];
  right.textContent = String(list.length);
  populateChangeSelect(list);
  if (!list.length) {
    body.replaceChildren(el('div', { class: 'muted', text: 'no addresses' }));
    return;
  }
  const wrap = el('div', { class: 'w-list' });
  for (const addr of list) wrap.append(el('div', { class: 'w-addr', text: addr }));
  body.replaceChildren(wrap);
}

// ── onboarding: init / restore ───────────────────────────────────────────────
function setOnboarding(on) {
  q('[data-onboard-panel]').hidden = !on;
  q('[data-status-panel]').hidden = on;
  q('[data-balances-panel]').hidden = on;
  q('[data-addresses-panel]').hidden = on;
  q('[data-send-panel]').hidden = on;
  if (on) {
    sendRendered = keysRendered = unlockRendered = false;
    q('[data-keys-panel]').hidden = true;
  } else {
    onboardRendered = false;
  }
}

function showOnboard() {
  if (onboardRendered) return;
  buildOnboard();
  onboardRendered = true;
}

function buildOnboard() {
  const body = q('[data-onboard-body]');
  body.replaceChildren();
  const tabInit = el('button', { class: 'tab', type: 'button', text: 'Initialize', 'aria-selected': 'true' });
  const tabRestore = el('button', { class: 'tab', type: 'button', text: 'Restore', 'aria-selected': 'false' });
  const pane = el('div', { 'data-onboard-pane': true });
  const select = (which) => {
    tabInit.setAttribute('aria-selected', String(which === 'init'));
    tabRestore.setAttribute('aria-selected', String(which === 'restore'));
    pane.replaceChildren(which === 'init' ? buildInitForm() : buildRestoreForm());
  };
  tabInit.addEventListener('click', () => select('init'));
  tabRestore.addEventListener('click', () => select('restore'));
  body.append(el('div', { class: 'tabs', role: 'tablist' }, tabInit, tabRestore), pane);
  select('init');
}

function onboardUnlockFailed(container, errEl, msg) {
  errEl.textContent = msg;
  errEl.hidden = false;
  if (!container.querySelector('[data-goto]')) {
    container.append(
      el('div', { class: 'w-row', 'data-goto': true }, el('button', { class: 'btn', type: 'button', text: 'Go to wallet', onclick: () => refresh() })),
    );
  }
}

function buildInitForm() {
  const pass = el('input', { type: 'password', class: 'input', autocomplete: 'new-password', spellcheck: 'false' });
  const passConfirm = el('input', { type: 'password', class: 'input', autocomplete: 'new-password', spellcheck: 'false' });
  const mnemonicPass = el('input', { type: 'password', class: 'input', autocomplete: 'off', spellcheck: 'false', placeholder: 'optional' });
  const strength = el('select', { class: 'select' });
  for (const n of [12, 15, 18, 21, 24]) {
    const opt = el('option', { value: String(n), text: `${n} words` });
    if (n === 24) opt.selected = true;
    strength.append(opt);
  }
  const err = el('div', { class: 'banner banner--err', hidden: true });
  const btn = el('button', { class: 'btn btn--primary', type: 'submit', text: 'Generate wallet' });
  return el(
    'form',
    {
      class: 'w-form',
      onsubmit: async (ev) => {
        ev.preventDefault();
        err.hidden = true;
        if (!pass.value) return fail(err, 'Choose a wallet password.');
        if (pass.value !== passConfirm.value) return fail(err, 'Passwords do not match.');
        const chosenPass = pass.value;
        btn.disabled = true;
        submitInFlight = true;
        const res = await api.wallet.init({ pass: chosenPass, mnemonicPass: mnemonicPass.value, strength: Number(strength.value) });
        submitInFlight = false;
        btn.disabled = false;
        pass.value = passConfirm.value = mnemonicPass.value = '';
        if (res.status === 403) return;
        if (!res.ok) return fail(err, res.reason || `init failed (${res.status})`);
        showMnemonicGate(res.data.mnemonic, chosenPass);
      },
    },
    field('Wallet password', pass),
    field('Confirm password', passConfirm),
    field('Mnemonic passphrase (BIP39, optional)', mnemonicPass),
    field('Mnemonic strength', strength),
    el('div', { class: 'banner banner--warn', text: EXT_WARNING }),
    err,
    el('div', { class: 'w-row' }, btn),
  );
}

function fail(errEl, msg) {
  errEl.textContent = msg;
  errEl.hidden = false;
}

function showMnemonicGate(mnemonic, chosenPass) {
  const pane = q('[data-onboard-pane]');
  pane.replaceChildren();
  mnemonicGateOpen = true; // suspend polling + guard navigation
  const pre = el('pre', { class: 'w-mnemonic', 'data-mnemonic': true });
  pre.textContent = mnemonic; // the ONLY place the phrase lives
  const ack = el('input', { type: 'checkbox' });
  const cont = el('button', { class: 'btn btn--primary', type: 'button', text: 'Continue', disabled: true });
  ack.addEventListener('change', () => {
    cont.disabled = !ack.checked;
  });
  const err = el('div', { class: 'banner banner--err', hidden: true });
  cont.addEventListener('click', async () => {
    pre.textContent = ''; // wipe the phrase before the round-trip
    mnemonicGateOpen = false; // phrase gone — nav guard + poll suspend lift
    cont.disabled = true;
    let pass = chosenPass;
    submitInFlight = true;
    const res = await api.wallet.unlock(pass);
    submitInFlight = false;
    pass = null;
    if (res.status === 403) return;
    if (res.ok) refresh();
    else onboardUnlockFailed(pane, err, `Wallet created but unlock failed: ${res.reason || ''}. Unlock it from the status view.`);
  });
  pane.append(
    el('div', { class: 'banner banner--warn', text: 'Write this recovery phrase down. It is shown once, never stored by this page, and is the only way to recover the wallet.' }),
    pre,
    el('div', { class: 'banner banner--warn', text: EXT_WARNING }),
    el('label', { class: 'w-check' }, ack, el('span', { text: 'I have written this recovery phrase down somewhere safe.' })),
    err,
    el('div', { class: 'w-row' }, cont),
  );
}

function buildRestoreForm() {
  const mnemonic = el('textarea', { class: 'textarea', rows: '3', autocomplete: 'off', spellcheck: 'false', placeholder: '12–24 word recovery phrase' });
  const pass = el('input', { type: 'password', class: 'input', autocomplete: 'new-password', spellcheck: 'false' });
  const passConfirm = el('input', { type: 'password', class: 'input', autocomplete: 'new-password', spellcheck: 'false' });
  const mnemonicPass = el('input', { type: 'password', class: 'input', autocomplete: 'off', spellcheck: 'false', placeholder: 'optional' });
  const modern = el('input', { type: 'checkbox' });
  const err = el('div', { class: 'banner banner--err', hidden: true });
  const btn = el('button', { class: 'btn btn--primary', type: 'submit', text: 'Restore wallet' });
  return el(
    'form',
    {
      class: 'w-form',
      onsubmit: async (ev) => {
        ev.preventDefault();
        err.hidden = true;
        if (!mnemonic.value.trim()) return fail(err, 'Enter the recovery phrase.');
        if (!pass.value) return fail(err, 'Choose a wallet password.');
        if (pass.value !== passConfirm.value) return fail(err, 'Passwords do not match.');
        const chosenPass = pass.value;
        const usePre1627 = !modern.checked;
        btn.disabled = true;
        submitInFlight = true;
        const res = await api.wallet.restore({ mnemonic: mnemonic.value.trim(), mnemonicPass: mnemonicPass.value, pass: chosenPass, usePre1627KeyDerivation: usePre1627 });
        mnemonic.value = pass.value = passConfirm.value = mnemonicPass.value = '';
        if (res.status === 403) {
          submitInFlight = false;
          btn.disabled = false;
          return;
        }
        if (!res.ok) {
          submitInFlight = false;
          btn.disabled = false;
          return fail(err, res.reason || `restore failed (${res.status})`);
        }
        let pass2 = chosenPass;
        const u = await api.wallet.unlock(pass2);
        submitInFlight = false;
        btn.disabled = false;
        pass2 = null;
        if (u.status === 403) return;
        if (u.ok) refresh();
        else onboardUnlockFailed(q('[data-onboard-pane]'), err, `Wallet restored but unlock failed: ${u.reason || ''}. Unlock it from the status view.`);
      },
    },
    field('Recovery phrase', mnemonic),
    field('Wallet password', pass),
    field('Confirm password', passConfirm),
    field('Mnemonic passphrase (BIP39, optional)', mnemonicPass),
    el('label', { class: 'w-check' }, modern, el('span', { text: 'Advanced — use modern EIP-3 derivation (leave unchecked to match a CLI restore).' })),
    el('div', { class: 'banner banner--warn', text: EXT_WARNING }),
    err,
    el('div', { class: 'w-row' }, btn),
  );
}

// ── send payment ─────────────────────────────────────────────────────────────
function showSendPanel() {
  if (sendRendered) return;
  buildSendForm();
  sendRendered = true;
}

function setSendEnabled(unlocked) {
  const btn = q('[data-send-submit]');
  const note = q('[data-send-locked]');
  if (btn) btn.disabled = !unlocked;
  if (note) note.hidden = unlocked;
}

function showSendMsg(kind, text) {
  const m = q('[data-send-msg]');
  if (!m) return;
  m.className = `banner banner--${kind}`;
  m.textContent = text;
  m.hidden = false;
}

function buildSendForm() {
  const body = q('[data-send-body]');
  body.replaceChildren();
  const rows = el('div', { 'data-send-rows': true, class: 'w-list' }, recipientRow());
  const addBtn = el('button', { class: 'btn', type: 'button', text: '+ recipient', onclick: () => rows.append(recipientRow()) });
  const submit = el('button', { 'data-send-submit': true, class: 'btn btn--primary', type: 'button', text: 'Review & send', onclick: onReviewSend });
  const locked = el('div', { 'data-send-locked': true, class: 'muted', hidden: true, text: 'Unlock the wallet to send.' });
  const msg = el('div', { 'data-send-msg': true, class: 'banner', hidden: true });
  body.append(rows, el('div', { class: 'w-row' }, addBtn, submit), locked, msg);
}

function recipientRow() {
  const addr = el('input', { class: 'input w-r-addr', 'data-r-addr': true, placeholder: 'recipient address (9…)', autocomplete: 'off', spellcheck: 'false' });
  const value = el('input', { class: 'input w-r-value', 'data-r-value': true, placeholder: 'amount (ERG)', inputmode: 'decimal', autocomplete: 'off' });
  const tokens = el('div', { class: 'w-tokens' });
  const addTok = el('button', { class: 'btn btn--sm', type: 'button', text: '+ token', onclick: () => tokens.append(tokenRow()) });
  const remove = el('button', { class: 'btn btn--sm', type: 'button', text: 'remove recipient', onclick: (ev) => ev.target.closest('[data-recipient]').remove() });
  return el(
    'div',
    { class: 'w-recipient', 'data-recipient': true },
    el('div', { class: 'w-row' }, addr, remove),
    el('div', { class: 'w-row' }, value),
    tokens,
    el('div', { class: 'w-row' }, addTok),
  );
}

function tokenRow() {
  const id = el('input', { class: 'input w-t-id', 'data-t-id': true, placeholder: 'tokenId (hex)', autocomplete: 'off', spellcheck: 'false' });
  const amt = el('input', { class: 'input w-t-amt', 'data-t-amt': true, placeholder: 'amount', inputmode: 'numeric', autocomplete: 'off' });
  const rm = el('button', { class: 'btn btn--sm', type: 'button', text: '×', onclick: (ev) => ev.target.closest('[data-token]').remove() });
  return el('div', { class: 'w-token w-row', 'data-token': true }, id, amt, rm);
}

// Parse recipient rows into the /wallet/payment/send body. Amounts are parsed
// with exact BigInt arithmetic and rejected if they exceed the safe JSON
// integer range (the wire format is a JSON number), so nothing is silently
// corrupted by float math.
function collectRequests() {
  const recipients = Array.from(root.querySelectorAll('[data-recipient]'));
  if (!recipients.length) return { error: 'Add at least one recipient.' };
  const requests = [];
  let totalNano = 0n;
  for (const [i, row] of recipients.entries()) {
    const address = row.querySelector('[data-r-addr]').value.trim();
    const ergStr = row.querySelector('[data-r-value]').value.trim();
    if (!address) return { error: `Recipient ${i + 1}: address is required.` };
    let value;
    try {
      value = nanoErgFromDecimal(ergStr);
    } catch {
      return { error: `Recipient ${i + 1}: enter a valid ERG amount (max 9 decimals).` };
    }
    if (value <= 0n) return { error: `Recipient ${i + 1}: amount must be greater than 0.` };
    if (value > MAX_SAFE) return { error: `Recipient ${i + 1}: amount is too large to submit safely.` };
    totalNano += value;
    const assets = [];
    for (const [j, t] of Array.from(row.querySelectorAll('[data-token]')).entries()) {
      const tokenId = t.querySelector('[data-t-id]').value.trim();
      const amtStr = t.querySelector('[data-t-amt]').value.trim();
      if (!tokenId && !amtStr) continue;
      if (!tokenId) return { error: `Recipient ${i + 1}, token ${j + 1}: tokenId is required.` };
      if (!/^\d+$/.test(amtStr)) return { error: `Recipient ${i + 1}, token ${j + 1}: amount must be a positive integer.` };
      const amount = BigInt(amtStr);
      if (amount <= 0n) return { error: `Recipient ${i + 1}, token ${j + 1}: amount must be greater than 0.` };
      if (amount > MAX_SAFE) return { error: `Recipient ${i + 1}, token ${j + 1}: amount is too large to submit safely.` };
      assets.push({ tokenId, amount: Number(amount) });
    }
    requests.push({ address, value: Number(value), assets });
  }
  return { requests, totalNano };
}

function onReviewSend() {
  const m = q('[data-send-msg]');
  if (m) m.hidden = true;
  const { requests, totalNano, error } = collectRequests();
  if (error) {
    showSendMsg('err', error);
    return;
  }
  showConfirm(requests, totalNano);
}

function showConfirm(requests, totalNano) {
  const lines = el('div', { class: 'kv' });
  for (const req of requests) {
    const k = el('div', { class: 'k v--hash', text: truncMiddle(req.address, 10, 8) });
    k.title = req.address;
    const tokNote = req.assets.length ? ` + ${req.assets.length} token${req.assets.length > 1 ? 's' : ''}` : '';
    lines.append(k, el('div', { class: 'v', text: `${erg(req.value)} ERG${tokNote}` }));
  }
  const dlg = el('dialog', { class: 'dialog' });
  const form = el(
    'form',
    { method: 'dialog', class: 'dialog__body' },
    el('h3', { class: 'micro-label', text: 'Confirm payment' }),
    el('div', { class: 'muted', text: `${requests.length} recipient${requests.length > 1 ? 's' : ''} · total ${erg(totalNano)} ERG (plus network fee)` }),
    lines,
    el(
      'div',
      { class: 'dialog__actions' },
      el('button', { class: 'btn', value: 'cancel', type: 'submit', text: 'Cancel' }),
      el('button', { class: 'btn btn--primary', value: 'confirm', type: 'submit', text: 'Confirm send' }),
    ),
  );
  dlg.append(form);
  document.body.append(dlg);
  dlg.addEventListener('close', () => {
    if (dlg.returnValue === 'confirm') doSend(requests);
    dlg.remove();
  });
  dlg.showModal();
}

async function doSend(requests) {
  const btn = q('[data-send-submit]');
  if (btn) btn.disabled = true;
  submitInFlight = true;
  showSendMsg('info', 'Building, signing and submitting — this can take a few seconds…');
  const res = await api.wallet.send(requests);
  submitInFlight = false;
  if (res.status === 403) return;
  if (res.ok) {
    const txId = res.data && res.data.txId;
    // Rebuild the form so the same draft can't be resubmitted, then re-show
    // the success message (buildSendForm replaces the message element).
    buildSendForm();
    setSendEnabled(true);
    showSendMsg('ok', `Submitted. txId: ${txId || ''}`);
  } else {
    const reason = res.reason || `send failed (${res.status})`;
    showSendMsg('err', reason === 'wallet_locked' ? 'Wallet is locked — unlock it above and try again. Your draft is preserved.' : `Send failed: ${reason}`);
    if (btn) btn.disabled = false;
  }
}

// ── keys: derive + change address ────────────────────────────────────────────
function showKeysPanel() {
  q('[data-keys-panel]').hidden = false;
  if (keysRendered) return;
  buildKeysForm();
  keysRendered = true;
}

function showKeyMsg(sel, kind, text) {
  const m = q(sel);
  if (!m) return;
  m.className = `banner banner--${kind}`;
  m.textContent = text;
  m.hidden = false;
}

function buildKeysForm() {
  const body = q('[data-keys-body]');
  body.replaceChildren();
  const deriveBtn = el('button', { class: 'btn', type: 'button', text: 'Derive next key', onclick: deriveNextKey });
  const deriveMsg = el('div', { 'data-derive-msg': true, class: 'banner', hidden: true });
  const select = el('select', { 'data-change-select': true, class: 'select' });
  const changeBtn = el('button', { class: 'btn', type: 'button', text: 'Set change address', onclick: updateChangeAddress });
  const changeMsg = el('div', { 'data-change-msg': true, class: 'banner', hidden: true });
  body.append(
    el('div', { class: 'w-label', text: 'Derive a new address' }),
    el('div', { class: 'w-row' }, deriveBtn),
    deriveMsg,
    el('div', { class: 'w-label', text: 'Change address (must be a tracked address)' }),
    el('div', { class: 'w-row' }, select, changeBtn),
    changeMsg,
  );
}

async function deriveNextKey() {
  const res = await api.wallet.deriveNextKey();
  if (res.status === 403) return;
  if (res.ok) {
    showKeyMsg('[data-derive-msg]', 'info', `Derived ${res.data.derivationPath} → ${res.data.address}`);
    refreshAddresses();
  } else {
    showKeyMsg('[data-derive-msg]', 'err', res.reason || `derive failed (${res.status})`);
  }
}

async function updateChangeAddress() {
  const sel = q('[data-change-select]');
  const address = sel && sel.value;
  if (!address) {
    showKeyMsg('[data-change-msg]', 'err', 'Select an address first (derive one if the list is empty).');
    return;
  }
  const res = await api.wallet.updateChangeAddress(address);
  if (res.status === 403) return;
  if (res.ok) {
    showKeyMsg('[data-change-msg]', 'info', 'Change address updated.');
    refresh();
  } else {
    showKeyMsg('[data-change-msg]', 'err', res.reason || `update failed (${res.status})`);
  }
}

function populateChangeSelect(list) {
  const sel = q('[data-change-select]');
  if (!sel) return;
  const prev = sel.value;
  sel.replaceChildren();
  for (const addr of list) sel.append(el('option', { value: addr, text: truncMiddle(addr, 16, 10) }));
  if (list.includes(prev)) sel.value = prev;
}

// ── refresh ──────────────────────────────────────────────────────────────────
async function refresh() {
  if (!root || q('[data-wallet-app]').hidden) return;
  const res = await api.wallet.status();
  if (res.status === 403) return; // auth subscription re-prompts
  if (!res.ok) {
    q('[data-status-body]').replaceChildren(
      el('div', { class: 'muted', text: res.status === 0 ? 'Node unreachable — retrying…' : `/wallet/status returned ${res.status} (${res.reason || 'error'}).` }),
    );
    return;
  }
  const s = res.data;
  renderScanBanner(s);
  if (!s.isInitialized) {
    setOnboarding(true);
    showOnboard();
    return;
  }
  setOnboarding(false);
  renderStatusPanel(s);
  showSendPanel();
  setSendEnabled(s.isUnlocked);
  if (s.isUnlocked) {
    refreshBalances();
    refreshAddresses();
    showKeysPanel();
  } else {
    lockedNotes();
  }
}
