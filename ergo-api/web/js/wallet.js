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
import { subscribe, promptAuthorize, CONFIGURE_API_KEY, getApiKey } from './auth.js';
import { erg, num, truncMiddle } from './format.js';
import { copyBtn } from './table.js';
import { fetchTokenMeta, tokenName, getTokenMeta } from './token-meta.js';
import { createWalletBuilder } from './wallet-builder.js';
import { decimal } from './wallet-transaction.js';

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
let keysRendered = false;
let unlockRendered = false;
// Last-fetched wallet token balances ({tokenId, amount}), so the send form's
// token picker can offer "what you actually have" instead of a blank hex
// field. Refreshed every refreshBalances() poll tick.
let myAssets = [];
let builder = null, walletBalance = null, walletStatus = null;
let activeTab = 'assets', assetPage = 0, activityPage = 0, generation = 0, refreshing = false;
let assetsRendered = false;
let metadataCheckedAt = 0;
let walletAccessKey = '';
const PAGE_SIZE = 12;

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
    <div class="pg-head">
      <div>
        <h1 class="pg-title">Wallet</h1>
        <p class="pg-description">Your assets. Your addresses. Every transaction, under your control.</p>
      </div>
    </div>
    <div class="ov-prompt banner banner--info" data-wallet-prompt hidden></div>
    <section class="panel" data-wallet-preauth hidden>
      <div class="panel__head"><h2 class="panel__title">Your wallet, on your node</h2><span class="pill">Operator access required</span></div>
      <div class="panel__body w-preauth">
        <p>Manage your funds using the wallet built into this node. Authorize to view your wallet and access its controls; wallet unlocking is a separate step.</p>
        <ul class="w-features">
          <li><b>Balances &amp; addresses</b><span>Review confirmed and pending ERG, tokens, and receiving addresses.</span></li>
          <li><b>Send payments</b><span>Build and review transactions before signing and broadcasting.</span></li>
          <li><b>Mining rewards</b><span>Collect matured mining rewards into a receiving address.</span></li>
          <li><b>Recovery &amp; rescan</b><span>Restore an existing wallet or scan the chain for its history.</span></li>
        </ul>
        <p class="muted">The key is held in this browser session only and sent solely to this node.</p>
      </div>
    </section>
    <div class="wallet-workspace" data-wallet-app hidden>
      <div class="banner banner--warn" data-scan-banner hidden></div>
      <section class="panel" data-onboard-panel hidden>
        <div class="panel__head"><h2 class="panel__title">Set up wallet</h2></div>
        <div class="panel__body" data-onboard-body></div>
      </section>
      <section class="wallet-hero" data-status-panel>
        <div class="wallet-hero__balance">
          <div class="wallet-eyebrow">YOUR NODE WALLET <span data-status-dot></span></div>
          <span class="wallet-hero__label">Available balance</span>
          <div class="wallet-hero__amount"><strong data-wallet-amount>—</strong><span>ERG</span></div>
          <div class="wallet-hero__actions" data-wallet-actions></div>
          <div class="wallet-hero__breakdown" data-wallet-breakdown></div>
        </div>
        <div class="wallet-hero__status">
          <div class="wb-heading"><h2>Wallet access</h2><div data-status-right></div></div>
          <div data-status-body></div>
        </div>
      </section>
      <div class="wallet-tabs" role="tablist" aria-label="Wallet sections" data-wallet-tabs></div>
      <section class="panel wallet-view" data-balances-panel data-wallet-view="assets" id="wallet-assets" role="tabpanel" aria-labelledby="wallet-tab-assets">
        <div class="panel__head"><h2 class="panel__title">Your assets</h2><div data-balances-right></div></div>
        <div class="panel__body" data-balances-body></div>
      </section>
      <section class="panel wallet-view" data-send-panel data-wallet-view="build" id="wallet-build" role="tabpanel" aria-labelledby="wallet-tab-build" hidden>
        <div class="panel__head"><h2 class="panel__title">Build a transaction</h2><span class="muted">Compose → Review → Confirm</span></div>
        <div class="panel__body" data-send-body></div>
      </section>
      <section class="panel wallet-view" data-addresses-panel data-wallet-view="receive" id="wallet-receive" role="tabpanel" aria-labelledby="wallet-tab-receive" hidden>
        <div class="panel__head"><h2 class="panel__title">Receive ERG &amp; tokens</h2><div data-addresses-right></div></div>
        <div class="panel__body" data-addresses-body></div>
      </section>
      <section class="panel wallet-view" data-wallet-view="activity" id="wallet-activity" role="tabpanel" aria-labelledby="wallet-tab-activity" hidden>
        <div class="panel__head"><h2 class="panel__title">Wallet activity</h2><span class="muted">Confirmed on chain</span></div>
        <div class="panel__body" data-activity-body></div>
      </section>
      <section class="panel wallet-view" data-keys-panel data-wallet-view="manage" id="wallet-manage" role="tabpanel" aria-labelledby="wallet-tab-manage" hidden>
        <div class="panel__head"><h2 class="panel__title">Wallet management</h2></div>
        <div class="panel__body" data-keys-body></div>
      </section>
    </div>`;
  for (const [id, title] of [['assets', 'Assets'], ['build', 'Build transaction'], ['receive', 'Receive'], ['activity', 'Activity'], ['manage', 'Manage']]) {
    const tab = el('button', { type: 'button', role: 'tab', id: 'wallet-tab-' + id,
      'aria-controls': 'wallet-' + id, 'aria-selected': id === activeTab ? 'true' : 'false',
      tabindex: id === activeTab ? '0' : '-1', text: title, onclick: () => selectTab(id) });
    tab.addEventListener('keydown', e => {
      const tabs = [...q('[data-wallet-tabs]').children], index = tabs.indexOf(tab);
      const next = e.key === 'ArrowRight' ? (index + 1) % tabs.length : e.key === 'ArrowLeft' ? (index + tabs.length - 1) % tabs.length : e.key === 'Home' ? 0 : e.key === 'End' ? tabs.length - 1 : -1;
      if (next < 0) return;
      e.preventDefault(); tabs[next].click(); tabs[next].focus();
    });
    q('[data-wallet-tabs]').append(tab);
  }
  q('[data-wallet-actions]').append(
    el('button', { class: 'btn btn--primary', type: 'button', text: '↗ Build transaction', onclick: () => selectTab('build') }),
    el('button', { class: 'btn', type: 'button', text: '↓ Receive', onclick: () => selectTab('receive') }),
  );
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

// Veto navigation while a recovery phrase is on screen OR an onboarding/unlock/
// send request is still in flight (leaving mid-init would scrub the pane the
// generated mnemonic must render into — a funds-safety loss).
export function canLeave() {
  if (mnemonicGateOpen) {
    return window.confirm(
      'Your recovery phrase is on screen and has not been confirmed saved. ' +
        'Leaving discards it permanently. Leave anyway?',
    );
  }
  if (submitInFlight) {
    return window.confirm(
      'A wallet operation is still in progress — its result (including a freshly ' +
        'generated recovery phrase) may be lost. Leave anyway?',
    );
  }
  if (builder?.isDirty()) return window.confirm('Leave the wallet and discard the transaction draft?');
  return true;
}

// ── auth gate + secret scrub ─────────────────────────────────────────────────
function renderAuthGate(s) {
  if (!root) return;
  const key = getApiKey();
  if (key !== walletAccessKey) { scrubSecrets(); walletAccessKey = key; }
  const blocked = s === 'none' || s === 'invalid' || s === 'unconfigured';
  q('[data-wallet-prompt] span').textContent = s === 'unconfigured'
    ? CONFIGURE_API_KEY : 'Authorize with the operator api_key to use the wallet.';
  q('[data-wallet-prompt]').hidden = !blocked;
  q('[data-wallet-preauth]').hidden = !blocked;
  q('[data-wallet-app]').hidden = blocked;
  if (blocked) {
    scrubSecrets();
  } else {
    refresh();
  }
}

function scrubSecrets() {
  if (!root) return;
  generation++;
  builder?.dispose(); builder = null;
  walletBalance = walletStatus = null; assetsRendered = false;
  q('[data-wallet-amount]').textContent = '—';
  q('[data-wallet-breakdown]').replaceChildren();
  for (const sel of ['[data-balances-body]', '[data-addresses-body]', '[data-activity-body]', '[data-status-body]']) q(sel)?.replaceChildren();
  for (const inp of root.querySelectorAll('input[type="password"]')) inp.value = '';
  const pre = q('[data-mnemonic]');
  if (pre) pre.textContent = '';
  mnemonicGateOpen = false;
  onboardRendered = keysRendered = unlockRendered = false;
  myAssets = [];
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
  if (right.dataset.access !== String(s.isUnlocked)) {
    right.replaceChildren();
    right.dataset.access = String(s.isUnlocked);
  }

  let kvWrap = q('[data-status-kv]');
  if (!kvWrap) {
    body.replaceChildren();
    kvWrap = el('div', { 'data-status-kv': true });
    body.append(kvWrap);
  }

  const kv = el('div', { class: 'wallet-access' },
    el('strong', { class: s.isUnlocked ? 'wallet-access__ready' : '', text: s.isUnlocked ? 'Unlocked & ready' : 'Wallet locked' }),
    el('p', { class: 'wb-note', text: s.isUnlocked ? 'Keys remain on your node. Every payment starts with an unsigned review.' : 'Unlock to view assets and prepare transactions.' }),
    kvRows([['Scanned through block', num(s.walletHeight)], ['Change address', truncMiddle(s.changeAddress || '', 12, 8) || '—']]),
  );
  if (s.error) kv.append(el('div', { class: 'banner banner--warn', text: s.error }));
  kvWrap.replaceChildren(kv);

  if (s.isUnlocked) {
    const uw = q('[data-unlock-wrap]');
    if (uw) uw.remove();
    unlockRendered = false;
    if (!right.querySelector('button')) right.append(el('button', { class: 'btn btn--danger btn--sm', text: 'Lock', onclick: lockWallet }));
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
  builder?.dispose(); builder = null;
  walletBalance = null; myAssets = []; assetsRendered = false;
  q('[data-wallet-amount]').textContent = '—';
  q('[data-wallet-breakdown]').replaceChildren();
  for (const [sel, text] of [['[data-balances-body]', 'Unlock to view your assets.'], ['[data-addresses-body]', 'Unlock to view receiving addresses.'], ['[data-activity-body]', 'Unlock to view wallet activity.'], ['[data-send-body]', 'Unlock to build a transaction.'], ['[data-keys-body]', 'Unlock to manage this wallet.']]) q(sel).replaceChildren(el('p', { class: 'wb-note', text }));
  keysRendered = false;
  q('[data-balances-right]').textContent = '';
  q('[data-addresses-right]').textContent = '';
}

function selectTab(id, focus = false) {
  activeTab = id;
  q('[data-wallet-app]').classList.toggle('wallet-workspace--compact', id !== 'assets');
  for (const tab of q('[data-wallet-tabs]').children) {
    const selected = tab.id === 'wallet-tab-' + id;
    tab.setAttribute('aria-selected', String(selected)); tab.tabIndex = selected ? 0 : -1;
    if (selected && focus) tab.focus();
  }
  for (const panel of root.querySelectorAll('[data-wallet-view]')) panel.hidden = panel.dataset.walletView !== id;
  if (id === 'activity' && walletStatus?.isUnlocked) refreshActivity();
}

async function refreshBalances(epoch = generation) {
  const res = await api.wallet.balance();
  if (epoch !== generation || res.status === 403) return;
  const body = q('[data-balances-body]');
  if (!res.ok) {
    walletBalance = null; myAssets = []; assetsRendered = false;
    q('[data-wallet-amount]').textContent = '—';
    q('[data-wallet-breakdown]').replaceChildren(el('span', { text: 'Balance unavailable' }));
    body.replaceChildren(el('p', { class: 'banner banner--warn', text: res.data?.detail || res.reason || 'Balance unavailable. Retrying…' }));
    builder?.update(null, walletStatus);
    return;
  }
  walletBalance = res.data; myAssets = walletBalance.assets || [];
  q('[data-wallet-amount]').textContent = decimal(walletBalance.nanoErg.available);
  const b = walletBalance.nanoErg;
  q('[data-wallet-breakdown]').replaceChildren(...[
    ['Confirmed', decimal(b.confirmed) + ' ERG'],
    ['Re-emission reserve', decimal(b.reserved) + ' ERG'],
    ['Immature rewards', decimal(b.immature) + ' ERG'],
  ].map(([label, value]) => el('div', {}, el('span', { text: label }), el('strong', { text: value }))));
  if (walletBalance.unconfirmed) {
    const p = walletBalance.unconfirmed;
    q('[data-wallet-breakdown]').append(el('div', { class: 'wallet-pending' },
      el('span', { text: 'Pending · direct wallet transfers' }),
      el('strong', { text: '+' + decimal(p.incomingNanoErg) + ' / −' + decimal(p.outgoingNanoErg) + ' ERG' })));
  }
  q('[data-balances-right]').textContent = num(myAssets.length) + ' token types';
  if (!assetsRendered) {
    const search = el('input', { type: 'search', class: 'input', 'data-asset-search': true, placeholder: 'Search by token name or ID', 'aria-label': 'Search wallet assets', oninput: () => { assetPage = 0; renderAssets(); } });
    body.replaceChildren(el('div', { class: 'wallet-assets-toolbar' }, search, el('span', { class: 'muted', 'data-asset-count': true })),
      el('p', { class: 'wb-note', 'data-asset-note': true }), el('div', { 'data-asset-list': true }),
      el('div', { class: 'wallet-pagination', 'data-asset-pages': true }));
    assetsRendered = true;
  }
  renderAssets(); builder?.update(walletBalance, walletStatus);
  if (Date.now() - metadataCheckedAt > 60_000) {
    metadataCheckedAt = Date.now();
    await fetchTokenMeta(myAssets.map(a => a.tokenId));
  }
  if (epoch !== generation) return;
  renderAssets();
}

function renderAssets() {
  if (!assetsRendered || !q('[data-asset-list]')) return;
  const search = q('[data-asset-search]').value.trim().toLowerCase();
  const list = myAssets.filter(a => (a.tokenId + ' ' + tokenName(a.tokenId)).toLowerCase().includes(search));
  const pages = Math.max(1, Math.ceil(list.length / PAGE_SIZE));
  assetPage = Math.min(assetPage, pages - 1);
  const listHost = q('[data-asset-list]');
  const signature = JSON.stringify([search, assetPage, myAssets, myAssets.map(a => getTokenMeta(a.tokenId))]);
  if (listHost.dataset.signature === signature) return;
  listHost.dataset.signature = signature;
  const unknown = myAssets.filter(a => !getTokenMeta(a.tokenId)).length;
  q('[data-asset-note]').textContent = unknown ? 'Some token metadata is unavailable. Those balances are shown in raw units until metadata resolves; verify tokens by their ID.' : 'Token names are supplied by their issuers. Verify the token ID before making a payment.';
  q('[data-asset-count]').textContent = search ? list.length + ' matches' : 'Confirmed holdings';
  const rows = list.slice(assetPage * PAGE_SIZE, (assetPage + 1) * PAGE_SIZE).map(a => {
    const meta = getTokenMeta(a.tokenId);
    const send = el('button', { class: 'btn btn--sm', type: 'button', text: 'Send', 'aria-label': 'Send ' + (tokenName(a.tokenId) || a.tokenId), onclick: () => { selectTab('build'); builder?.addToken(a.tokenId); } });
    return el('div', { class: 'wallet-asset' },
      el('span', { class: 'wallet-asset__mark', 'aria-hidden': true, text: a.tokenId.slice(0, 2).toUpperCase() }),
      el('div', { class: 'wallet-asset__identity' }, el('a', { href: '#explorer/token/' + a.tokenId, text: tokenName(a.tokenId) || 'Token · ' + a.tokenId.slice(0, 8) }),
        el('div', {}, el('code', { title: a.tokenId, text: truncMiddle(a.tokenId, 18, 12) }), copyBtn(a.tokenId))),
      el('div', { class: 'wallet-asset__amount' }, el('strong', { text: decimal(a.amount, meta?.decimals || 0) }), el('small', { text: meta ? (meta.decimals ? meta.decimals + ' decimals' : 'Whole units') : 'Raw units · metadata unavailable' })), send);
  });
  q('[data-asset-list]').replaceChildren(...(rows.length ? rows : [el('div', { class: 'wallet-empty', text: search ? 'No tokens match your search.' : 'No tokens in this wallet yet. Your ERG balance is shown above.' })]));
  const prev = el('button', { class: 'btn btn--sm', type: 'button', text: 'Previous', disabled: assetPage === 0, onclick: () => { assetPage--; renderAssets(); } });
  const next = el('button', { class: 'btn btn--sm', type: 'button', text: 'Next', disabled: assetPage + 1 >= pages, onclick: () => { assetPage++; renderAssets(); } });
  q('[data-asset-pages]').replaceChildren(el('span', { text: list.length ? (assetPage * PAGE_SIZE + 1) + '–' + Math.min((assetPage + 1) * PAGE_SIZE, list.length) + ' of ' + list.length : '0 assets' }), prev, next);
}

async function refreshActivity(epoch = generation) {
  const page = activityPage;
  const res = await api.wallet.transactions(page * PAGE_SIZE, PAGE_SIZE);
  if (epoch !== generation || page !== activityPage || !walletStatus?.isUnlocked) return;
  const body = q('[data-activity-body]');
  if (!res.ok) { body.replaceChildren(el('p', { class: 'wb-note', text: res.data?.detail || res.reason || 'Activity unavailable.' })); return; }
  const items = res.data.items || [];
  const signature = JSON.stringify([page, res.data]);
  if (body.dataset.signature === signature && body.childElementCount) return;
  body.dataset.signature = signature;
  const rows = items.map(t => el('div', { class: 'wallet-activity-row' },
    el('a', { class: 'wallet-activity-id', href: '#explorer/tx/' + t.txId, text: truncMiddle(t.txId, 18, 12), title: t.txId }),
    el('span', { text: 'Block ' + num(t.blockHeight) }),
    el('span', { text: t.walletInputBoxIds.length + ' wallet inputs · ' + t.walletOutputBoxIds.length + ' wallet outputs' }),
    el('a', { href: '#explorer/tx/' + t.txId, text: 'Details ↗' })));
  body.replaceChildren(el('p', { class: 'wb-note', text: 'Confirmed transactions involving this wallet. Open details for inputs, outputs and fees; search indexing may still be catching up.' }),
    ...rows, ...(rows.length ? [] : [el('div', { class: 'wallet-empty', text: 'No confirmed wallet transactions on this page.' })]),
    el('div', { class: 'wallet-pagination' }, el('span', { text: num(res.data.total) + ' transactions' }),
      el('button', { class: 'btn btn--sm', type: 'button', text: 'Previous', disabled: !page, onclick: () => { activityPage--; refreshActivity(); } }),
      el('button', { class: 'btn btn--sm', type: 'button', text: 'Next', disabled: (page + 1) * PAGE_SIZE >= res.data.total, onclick: () => { activityPage++; refreshActivity(); } })));
}

// Sweep matured miner-reward boxes into the wallet address (EIP-27-correct:
// burns the re-emission token, pays pay-to-reemission). Previews (dry-run),
// confirms the breakdown, then executes.
async function retrieveMaturedRewards() {
  const preview = await api.wallet.retrieveRewards({ dryRun: true });
  if (!preview.ok) {
    // Native endpoint: the actionable message is `detail` (e.g. "no matured
    // rewards", "fee below the minimum relay fee"); `reason` is the generic code.
    window.alert(preview.data?.detail || preview.reason || `preview failed (${preview.status})`);
    return;
  }
  const p = preview.data;
  // Amounts arrive as decimal nanoErg strings — format with the BigInt-based
  // `erg()` so large totals are not rounded by JS `Number`.
  const tokenLine =
    p.otherTokens && p.otherTokens.length
      ? `\n+ ${p.otherTokens.length} other token type(s) carried through`
      : '';
  const remainingLine =
    p.remaining > 0 ? `\n  (${p.remaining} more box(es) — run again after this)` : '';
  const ok = window.confirm(
    `Retrieve ${p.boxCount} matured reward box(es):\n` +
      `\n  gross matured:  ${erg(p.grossErg)} ERG` +
      `\n  re-emission:    ${erg(p.reemissionPaid)} ERG (paid to re-emission)` +
      `\n  fee:            ${erg(p.fee)} ERG` +
      `\n  net to you:     ${erg(p.netToDestination)} ERG` +
      `\n  destination:    ${p.destination}` +
      tokenLine +
      remainingLine +
      `\n\nSubmit this sweep?`,
  );
  if (!ok) return;
  // Pin the executed sweep to EXACTLY the inputs + destination the user just
  // confirmed, so a change-address update or a newly-matured reward between
  // preview and confirm can't submit a different sweep than was shown.
  const res = await api.wallet.retrieveRewards({
    dryRun: false,
    destination: p.destination,
    boxIds: p.boxIds,
    fee: p.fee,
  });
  if (!res.ok) {
    window.alert(res.data?.detail || res.reason || `retrieve failed (${res.status})`);
    return;
  }
  const more = res.data.remaining > 0 ? ` (${res.data.remaining} more — run again)` : '';
  window.alert(`Submitted sweep: ${res.data.txId}${more}`);
  refreshBalances();
}

async function refreshAddresses(epoch = generation) {
  const res = await api.wallet.addresses();
  if (epoch !== generation || res.status === 403) return;
  const body = q('[data-addresses-body]');
  if (!res.ok) { body.replaceChildren(el('p', { class: 'wb-note', text: res.reason || 'Addresses unavailable.' })); return; }
  const list = res.data || [];
  q('[data-addresses-right]').textContent = list.length + ' tracked';
  populateChangeSelect(list);
  // Keep copy feedback/focus stable during background polling.
  const signature = JSON.stringify([list, walletStatus?.changeAddress]);
  if (body.dataset.addressSignature === signature && body.childElementCount) return;
  body.dataset.addressSignature = signature;
  body.replaceChildren(el('p', { class: 'wb-note', text: 'Use a tracked address below to receive ERG or tokens on this node’s network. Copy the full address and verify it in the sending wallet.' }),
    ...list.map((addr, i) => el('div', { class: 'wallet-receive-card' },
      el('div', { class: 'wb-heading' }, el('strong', { text: 'Address ' + (i + 1) }), el('span', { class: 'pill', text: addr === walletStatus?.changeAddress ? 'Current change address' : 'Tracked address' })),
      el('code', { class: 'wallet-receive-address', text: addr }),
      el('div', { class: 'wb-actions' }, addressCopyButton(addr), el('a', { class: 'btn btn--sm', href: '#explorer/address/' + addr, text: 'View in explorer ↗' })))));
  if (!list.length) body.append(el('p', { class: 'wb-note', text: 'No tracked addresses. Create one from Manage.' }));
}

function addressCopyButton(address) {
  const button = el('button', { class: 'btn', type: 'button', text: 'Copy address' });
  button.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(address);
      button.textContent = 'Address copied';
    } catch { button.textContent = 'Select the address to copy manually'; }
    setTimeout(() => { button.textContent = 'Copy address'; }, 2000);
  });
  return button;
}

// ── onboarding: init / restore ───────────────────────────────────────────────
function setOnboarding(on) {
  q('[data-onboard-panel]').hidden = on === false;
  q('[data-status-panel]').hidden = on;
  q('[data-wallet-tabs]').hidden = on;
  for (const panel of root.querySelectorAll('[data-wallet-view]')) panel.hidden = on || panel.dataset.walletView !== activeTab;
  if (on) { keysRendered = unlockRendered = false; }
  else onboardRendered = false;
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
  if (!pane) return; // section was torn down mid-init; nothing to render into
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
  if (builder) return;
  const key = getApiKey(), epoch = generation;
  builder = createWalletBuilder(q('[data-send-body]'), {
    api: api.wallet,
    active: () => epoch === generation && key === getApiKey() && !q('[data-wallet-app]').hidden,
    onBusy: busy => { submitInFlight = busy; },
    onSent: () => refresh(),
  });
  builder.update(walletBalance, walletStatus);
}

// ── keys: derive + change address ────────────────────────────────────────────
function showKeysPanel() {
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
  const deriveBtn = el('button', { class: 'btn', type: 'button', text: 'Create receiving address', onclick: deriveNextKey });
  const deriveMsg = el('div', { 'data-derive-msg': true, class: 'banner', hidden: true });
  const select = el('select', { 'data-change-select': true, class: 'select' });
  const changeBtn = el('button', { class: 'btn', type: 'button', text: 'Set change address', onclick: updateChangeAddress });
  const changeMsg = el('div', { 'data-change-msg': true, class: 'banner', hidden: true });
  body.append(
    el('p', { class: 'wb-note', text: 'Create tracked receiving addresses and choose where transaction change returns. Changes here affect future builds.' }),
    el('div', { class: 'w-label', text: 'Create another receiving address' }),
    el('div', { class: 'w-row' }, deriveBtn),
    deriveMsg,
    el('div', { class: 'w-label', text: 'Change address (must be a tracked address)' }),
    el('div', { class: 'w-row' }, select, changeBtn),
    changeMsg,
    el('div', { class: 'wallet-management-rewards' }, el('h3', { text: 'Mining rewards' }),
      el('p', { class: 'wb-note', text: 'Collect matured rewards into your wallet. Preview shows the fee, required re-emission payment, and amount you receive before confirmation.' }),
      el('button', { class: 'btn', type: 'button', text: 'Preview reward retrieval', onclick: retrieveMaturedRewards })),
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
  if (!root || q('[data-wallet-app]').hidden || refreshing) return;
  refreshing = true;
  const epoch = generation;
  try {
    const res = await api.wallet.status();
    if (epoch !== generation || res.status === 403) return;
    if (!res.ok) {
      walletStatus = null; unlockRendered = false;
      q('[data-status-body]').replaceChildren(el('p', { class: 'banner banner--warn', text: 'Wallet status unavailable. Reconnecting…' }));
      return;
    }
    walletStatus = res.data;
    renderScanBanner(walletStatus);
    if (!walletStatus.isInitialized) { setOnboarding(true); showOnboard(); return; }
    setOnboarding(false); renderStatusPanel(walletStatus);
    if (walletStatus.isUnlocked) {
      showSendPanel(); showKeysPanel(); builder.update(walletBalance, walletStatus);
      await Promise.all([refreshBalances(epoch), refreshAddresses(epoch), ...(activeTab === 'activity' ? [refreshActivity(epoch)] : [])]);
    } else {
      lockedNotes();
    }
  } finally { refreshing = false; }
}
