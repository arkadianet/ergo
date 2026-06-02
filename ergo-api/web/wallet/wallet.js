"use strict";

/* Wallet UI — a thin remote control for the node's /wallet/* REST API.
   The browser never holds the master key, never derives, never signs:
   every operation is a fetch() to a /wallet/* route, authenticated with
   the operator api_key the user pastes on first visit. The key lives in
   this tab's sessionStorage and is sent as the `api_key` request header
   (Scala-parity name — lowercase, underscore), never in a URL.

   A self-contained IIFE module: a $ helper and a single fetch helper,
   self-initialising on DOMContentLoaded. No build
   step, no framework. Server-supplied strings are written via
   textContent only — never innerHTML — so nothing the API returns can
   inject markup. */

const Wallet = (() => {
  const $ = id => document.getElementById(id);

  /* ── DOM helper ─────────────────────────────────────────────────────
     el("button", {class:"w-btn", text:"Lock", onclick:fn}, ...children).
     `text` sets textContent; `on*` keys bind listeners; everything else
     is a plain attribute. No `html` branch by design. */
  function el(tag, props, ...kids) {
    const n = document.createElement(tag);
    if (props) {
      for (const k of Object.keys(props)) {
        const v = props[k];
        if (k === "class") n.className = v;
        else if (k === "text") n.textContent = v;
        else if (k.startsWith("on") && typeof v === "function") {
          n.addEventListener(k.slice(2), v);
        } else if (v !== false && v != null) {
          n.setAttribute(k, v === true ? "" : v);
        }
      }
    }
    for (const kid of kids) if (kid != null) n.append(kid);
    return n;
  }

  const fmtErg = n => (n == null ? "—" : (Number(n) / 1e9).toFixed(4));
  const fmtN = n => (n == null ? "—" : Number(n).toLocaleString("en-US"));
  function trunc(s, head = 10, tail = 8) {
    if (!s) return "—";
    return s.length <= head + tail + 1 ? s : `${s.slice(0, head)}…${s.slice(-tail)}`;
  }

  /* ── Key storage ────────────────────────────────────────────────── */
  const KEY_NAME = "ergo_api_key";
  const getKey = () => sessionStorage.getItem(KEY_NAME);
  const setKey = v => sessionStorage.setItem(KEY_NAME, v);
  const clearKey = () => sessionStorage.removeItem(KEY_NAME);

  /* ── Fetch helper ───────────────────────────────────────────────
     Injects the stashed api_key as a request header. Returns the raw
     Response so callers can branch on status (403 → re-prompt). */
  function walletFetch(path, opts = {}) {
    const headers = Object.assign({}, opts.headers);
    const key = getKey();
    if (key) headers["api_key"] = key;
    return fetch(path, Object.assign({ cache: "no-store" }, opts, { headers }));
  }

  // POST a JSON body to a /wallet/* route.
  function walletPostJson(path, body) {
    return walletFetch(path, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
  }

  // Parse a {reason, detail} error envelope without throwing.
  async function reasonOf(resp, fallback) {
    try {
      const j = await resp.json();
      return j.reason || j.detail || fallback;
    } catch (_) {
      return fallback;
    }
  }

  /* ── Auth gate ──────────────────────────────────────────────────── */
  function showAuthError(msg) {
    const e = $("wallet-auth-error");
    if (!e) return;
    e.textContent = msg;
    e.style.color = "var(--red)";
    e.hidden = false;
  }

  function showAuthPrompt() {
    stopPolling();
    $("wallet-app").hidden = true;
    $("wallet-logout").hidden = true;
    $("wallet-auth").hidden = false;
    const input = $("wallet-key-input");
    input.value = "";
    input.focus();
  }

  // The stashed key stopped working mid-session (rotated / revoked).
  function onAuthLost() {
    clearKey();
    // Drop memoised panes so re-auth rebuilds them fresh: a stale init /
    // restore form must not resurface with a passphrase still in its inputs.
    onboardRendered = false;
    sendRendered = false;
    keysRendered = false;
    unlockRendered = false;
    showAuthPrompt();
    showAuthError("Session key rejected (403). Re-enter the operator api_key.");
  }

  // Validate a candidate key by hitting /wallet/status once. 200 → good
  // (and the gate is configured); 403 → wrong/missing key.
  async function validateKey(candidate) {
    try {
      const r = await fetch("/wallet/status", {
        cache: "no-store",
        headers: { api_key: candidate },
      });
      return r.status === 200;
    } catch (_) {
      return false;
    }
  }

  async function onAuthSubmit(ev) {
    ev.preventDefault();
    const input = $("wallet-key-input");
    const candidate = input.value;
    if (!candidate) {
      showAuthError("Enter the operator api_key.");
      return;
    }
    const submit = $("wallet-key-submit");
    submit.disabled = true;
    const ok = await validateKey(candidate);
    submit.disabled = false;
    if (ok) {
      setKey(candidate);
      input.value = "";
      $("wallet-auth-error").hidden = true;
      enterApp();
    } else {
      clearKey();
      showAuthError("Key rejected (403). Check the node's api_key and retry.");
      input.value = "";
      input.focus();
    }
  }

  function logout() {
    stopPolling();
    clearKey();
    location.reload();
  }

  /* ── Status panel ───────────────────────────────────────────────── */
  function kvRows(rows) {
    const kv = el("div", { class: "kv" });
    for (const [label, value, cls] of rows) {
      kv.append(el("div", { class: "k", text: label }), el("div", { class: `v ${cls || ""}`, text: value }));
    }
    return kv;
  }

  // Built once and preserved across the 5 s poll. Rebuilding the unlock
  // form on every refresh would wipe the password the operator is mid-
  // typing (a fresh <input> resets value + focus). Reset on unlock /
  // onboarding / auth-loss so a stale password never lingers.
  let unlockRendered = false;

  function renderStatusPanel(s) {
    const dot = $("w-status-dot");
    dot.className = "panel-dot " + (s.isUnlocked ? "green" : s.isInitialized ? "orange" : "");

    const body = $("w-status-body");
    const right = $("w-status-right");
    right.replaceChildren();

    // Live status (KV) refreshes each poll; it lives in its own stable
    // sub-container so updating it never touches the unlock form below it.
    let kvWrap = $("w-status-kv");
    if (!kvWrap) {
      body.replaceChildren();
      kvWrap = el("div", { id: "w-status-kv" });
      body.append(kvWrap);
    }

    const changeAddr = el("div", { class: "v hash", text: trunc(s.changeAddress) });
    if (s.changeAddress) changeAddr.title = s.changeAddress;

    const kv = el("div", { class: "kv" });
    kv.append(
      el("div", { class: "k", text: "initialized" }),
      el("div", { class: `v ${s.isInitialized ? "green" : "dim"}`, text: String(s.isInitialized) }),
      el("div", { class: "k", text: "unlocked" }),
      el("div", { class: `v ${s.isUnlocked ? "green" : "dim"}`, text: String(s.isUnlocked) }),
      el("div", { class: "k", text: "change address" }),
      changeAddr,
      el("div", { class: "k", text: "wallet height" }),
      el("div", { class: "v", text: fmtN(s.walletHeight) }),
    );
    if (s.error) {
      kv.append(el("div", { class: "k", text: "error" }), el("div", { class: "v red", text: s.error }));
    }
    kvWrap.replaceChildren(kv);

    // refresh() routes the uninitialized state to the onboarding pane and
    // hides this panel, so by here the wallet is always initialized.
    if (s.isUnlocked) {
      const uw = $("w-unlock-wrap");
      if (uw) uw.remove();
      unlockRendered = false;
      right.append(el("button", { class: "w-btn danger", text: "Lock", onclick: lockWallet }));
    } else if (!unlockRendered) {
      // Build the unlock form ONCE; later polls leave it (and the password
      // being typed) untouched.
      const old = $("w-unlock-wrap");
      if (old) old.remove();
      body.append(el("div", { id: "w-unlock-wrap" }, renderUnlockForm()));
      unlockRendered = true;
    }
  }

  function renderUnlockForm() {
    const input = el("input", {
      type: "password", class: "w-input", placeholder: "wallet password",
      autocomplete: "off", spellcheck: "false",
    });
    const btn = el("button", { class: "w-btn primary", type: "submit", text: "Unlock" });
    const err = el("div", { class: "w-banner err", hidden: true, style: "margin-top:8px" });
    const form = el("form", {
      class: "w-row", style: "margin-top:10px",
      onsubmit: async ev => {
        ev.preventDefault();
        err.hidden = true;
        btn.disabled = true;
        let r;
        try {
          r = await walletPostJson("/wallet/unlock", { pass: input.value });
        } catch (_) {
          btn.disabled = false;
          err.textContent = "Network error reaching the node.";
          err.hidden = false;
          return;
        }
        btn.disabled = false;
        if (r.status === 403) return onAuthLost();
        if (r.ok) {
          input.value = "";
          refresh();
        } else {
          err.textContent = await reasonOf(r, `unlock failed (${r.status})`);
          err.hidden = false;
        }
      },
    }, input, btn);
    return el("div", null, form, err);
  }

  async function lockWallet() {
    let r;
    try {
      r = await walletFetch("/wallet/lock");
    } catch (_) {
      return;
    }
    if (r.status === 403) return onAuthLost();
    refresh();
  }

  /* ── Scan-invalidated banner ────────────────────────────────────── */
  function renderScanBanner(s) {
    const b = $("w-scan-banner");
    if (s.error === "scan_invalidated") {
      b.textContent =
        "Wallet scan invalidated — balances and addresses may be stale until a rescan. " +
        "Trigger one from the CLI/API (POST /wallet/rescan); the rescan UI is out of scope for v1.";
      b.hidden = false;
    } else {
      b.hidden = true;
    }
  }

  /* ── Reads: balances + addresses ────────────────────────────────── */
  function readsLockedNote(target, what) {
    $(target).replaceChildren(el("div", { class: "w-muted", text: `Unlock the wallet to view ${what}.` }));
  }

  async function refreshBalances() {
    let r;
    try {
      r = await walletFetch("/wallet/balances");
    } catch (_) {
      return;
    }
    if (r.status === 403) return onAuthLost();
    const body = $("w-balances-body");
    const right = $("w-balances-right");
    if (!r.ok) {
      right.textContent = "";
      body.replaceChildren(el("div", { class: "w-muted", text: await reasonOf(r, `balances unavailable (${r.status})`) }));
      return;
    }
    const b = await r.json();
    right.textContent = `height ${fmtN(b.height)}`;
    body.replaceChildren();
    body.append(
      kvRows([["confirmed", `${fmtErg(b.balance)} ERG`, "green"]]),
    );
    const assets = b.assets || [];
    if (assets.length) {
      const tokKv = el("div", { class: "kv", style: "margin-top:8px" });
      for (const a of assets) {
        const id = el("div", { class: "k hash", text: trunc(a.tokenId) });
        id.title = a.tokenId;
        tokKv.append(id, el("div", { class: "v", text: fmtN(a.amount) }));
      }
      body.append(el("div", { class: "w-muted", style: "margin:10px 0 4px", text: `tokens (${assets.length})` }), tokKv);
    } else {
      body.append(el("div", { class: "w-muted", style: "margin-top:8px", text: "no tokens" }));
    }
  }

  async function refreshAddresses() {
    let r;
    try {
      r = await walletFetch("/wallet/addresses");
    } catch (_) {
      return;
    }
    if (r.status === 403) return onAuthLost();
    const body = $("w-addresses-body");
    const right = $("w-addresses-right");
    if (!r.ok) {
      right.textContent = "";
      body.replaceChildren(el("div", { class: "w-muted", text: await reasonOf(r, `addresses unavailable (${r.status})`) }));
      return;
    }
    const list = await r.json();
    right.textContent = `${list.length}`;
    populateChangeSelect(list); // keep the change-address selector in sync
    body.replaceChildren();
    if (!list.length) {
      body.append(el("div", { class: "w-muted", text: "no addresses" }));
      return;
    }
    const wrap = el("div", { class: "w-list" });
    for (const addr of list) {
      wrap.append(el("div", { class: "w-addr", text: addr }));
    }
    body.append(wrap);
  }

  /* ── Onboarding: init / restore ─────────────────────────────────────
     Shown when the wallet is uninitialized. The 5 s poll is suspended for
     the duration of a submit flow (stopPolling): POST /wallet/init flips
     isInitialized=true server-side while the operator is still reading the
     mnemonic, and a poll-driven refresh would otherwise navigate away and
     destroy the only copy of the phrase. The phrase lives only in the
     <pre>.textContent; the chosen password lives only in a closure local,
     never sessionStorage / localStorage. */

  const EXT_WARNING =
    "Any browser extension with access to this page can read the mnemonic while it is on screen. " +
    "Prefer a clean browser profile; never reuse a mnemonic from another wallet.";

  let onboardRendered = false;

  // Toggle between the onboarding pane and the three initialized panels.
  function setOnboarding(on) {
    $("w-onboard").hidden = !on;
    $("w-status-panel").hidden = on;
    $("w-balances-panel").hidden = on;
    $("w-addresses-panel").hidden = on;
    $("w-send-panel").hidden = on;
    if (on) {
      sendRendered = false; // rebuild the send form fresh next time
      keysRendered = false;
      unlockRendered = false; // rebuild the unlock form fresh (no stale password)
      $("w-keys-panel").hidden = true; // keys panel shows only while unlocked
    }
    if (!on) onboardRendered = false; // rebuild onboarding fresh if it returns
  }

  function resumeLiveView() {
    // refresh() restarts polling via ensurePolling() once it sees the
    // initialized state.
    refresh();
  }

  function showOnboard() {
    if (onboardRendered) return;
    buildOnboard();
    onboardRendered = true;
  }

  function buildOnboard() {
    const body = $("w-onboard-body");
    body.replaceChildren();

    const tabInit = el("button", { class: "w-tab active", type: "button", text: "Initialize" });
    const tabRestore = el("button", { class: "w-tab", type: "button", text: "Restore" });
    const pane = el("div", { id: "w-onboard-pane" });

    const select = which => {
      tabInit.classList.toggle("active", which === "init");
      tabRestore.classList.toggle("active", which === "restore");
      pane.replaceChildren(which === "init" ? buildInitForm() : buildRestoreForm());
    };
    tabInit.addEventListener("click", () => select("init"));
    tabRestore.addEventListener("click", () => select("restore"));

    body.append(el("div", { class: "w-tabs" }, tabInit, tabRestore), pane);
    select("init");
  }

  function field(labelText, control) {
    return el("label", { class: "w-field" }, el("span", { class: "w-label", text: labelText }), control);
  }

  // Hand off to the live status view (which carries the standard unlock
  // form) after a create succeeded but the explicit unlock failed.
  function onboardUnlockFailed(container, errEl, msg) {
    errEl.textContent = msg;
    errEl.hidden = false;
    if (!container.querySelector(".w-goto")) {
      container.append(el("div", { class: "w-row w-goto", style: "margin-top:10px" },
        el("button", { class: "w-btn", type: "button", text: "Go to wallet", onclick: resumeLiveView })));
    }
  }

  function buildInitForm() {
    const pass = el("input", { type: "password", class: "w-input", autocomplete: "new-password", spellcheck: "false" });
    const passConfirm = el("input", { type: "password", class: "w-input", autocomplete: "new-password", spellcheck: "false" });
    const mnemonicPass = el("input", { type: "password", class: "w-input", autocomplete: "off", spellcheck: "false", placeholder: "optional" });
    const strength = el("select", { class: "w-input" });
    for (const n of [12, 15, 18, 21, 24]) {
      const opt = el("option", { value: String(n), text: `${n} words` });
      if (n === 24) opt.selected = true;
      strength.append(opt);
    }
    const err = el("div", { class: "w-banner err", hidden: true });
    const btn = el("button", { class: "w-btn primary", type: "submit", text: "Generate wallet" });

    return el("form", {
      class: "w-form",
      onsubmit: async ev => {
        ev.preventDefault();
        err.hidden = true;
        if (!pass.value) { err.textContent = "Choose a wallet password."; err.hidden = false; return; }
        if (pass.value !== passConfirm.value) { err.textContent = "Passwords do not match."; err.hidden = false; return; }
        const chosenPass = pass.value;
        btn.disabled = true;
        let r;
        try {
          r = await walletPostJson("/wallet/init", {
            pass: chosenPass, mnemonicPass: mnemonicPass.value, strength: Number(strength.value),
          });
        } catch (_) {
          btn.disabled = false;
          pass.value = ""; passConfirm.value = ""; mnemonicPass.value = "";
          err.textContent = "Network error reaching the node."; err.hidden = false; return;
        }
        btn.disabled = false;
        // Clear the passphrase fields from the DOM as soon as the request
        // resolves (success or failure); chosenPass is held in this local for
        // the explicit unlock that follows a successful init.
        pass.value = ""; passConfirm.value = ""; mnemonicPass.value = "";
        if (r.status === 403) return onAuthLost();
        if (!r.ok) {
          err.textContent = await reasonOf(r, `init failed (${r.status})`); err.hidden = false; return;
        }
        const { mnemonic } = await r.json();
        showMnemonicGate(mnemonic, chosenPass);
      },
    },
      field("Wallet password", pass),
      field("Confirm password", passConfirm),
      field("Mnemonic passphrase (BIP39, optional)", mnemonicPass),
      field("Mnemonic strength", strength),
      el("div", { class: "w-warn-text", text: EXT_WARNING }),
      err,
      el("div", { class: "w-row" }, btn),
    );
  }

  function showMnemonicGate(mnemonic, chosenPass) {
    const pane = $("w-onboard-pane");
    pane.replaceChildren();

    const pre = el("pre", { class: "w-mnemonic" });
    pre.textContent = mnemonic; // the ONLY place the mnemonic lives

    const ack = el("input", { type: "checkbox" });
    const cont = el("button", { class: "w-btn primary", type: "button", text: "Continue", disabled: true });
    ack.addEventListener("change", () => { cont.disabled = !ack.checked; });
    const err = el("div", { class: "w-banner err", hidden: true });

    cont.addEventListener("click", async () => {
      pre.textContent = ""; // wipe the phrase from the DOM before the round-trip
      cont.disabled = true;
      let pass = chosenPass;
      let r;
      try {
        r = await walletPostJson("/wallet/unlock", { pass });
      } catch (_) {
        pass = null;
        onboardUnlockFailed(pane, err, "Wallet created but unlock failed (network). Unlock it from the status view.");
        return;
      }
      pass = null; // dropped after use, never persisted
      if (r.status === 403) return onAuthLost();
      if (r.ok) {
        resumeLiveView();
      } else {
        onboardUnlockFailed(pane, err, `Wallet created but unlock failed: ${await reasonOf(r, "")}. Unlock it from the status view.`);
      }
    });

    pane.append(
      el("div", { class: "w-banner warn",
        text: "Write this recovery phrase down. It is shown once, never stored by this page, and is the only way to recover the wallet." }),
      pre,
      el("div", { class: "w-warn-text", text: EXT_WARNING }),
      el("label", { class: "w-check" }, ack, el("span", { text: "I have written this recovery phrase down somewhere safe." })),
      err,
      el("div", { class: "w-row" }, cont),
    );
  }

  function buildRestoreForm() {
    const mnemonic = el("textarea", { class: "w-textarea", rows: "3", autocomplete: "off", spellcheck: "false", placeholder: "12–24 word recovery phrase" });
    const pass = el("input", { type: "password", class: "w-input", autocomplete: "new-password", spellcheck: "false" });
    const passConfirm = el("input", { type: "password", class: "w-input", autocomplete: "new-password", spellcheck: "false" });
    const mnemonicPass = el("input", { type: "password", class: "w-input", autocomplete: "off", spellcheck: "false", placeholder: "optional" });
    const modern = el("input", { type: "checkbox" });
    const err = el("div", { class: "w-banner err", hidden: true });
    const btn = el("button", { class: "w-btn primary", type: "submit", text: "Restore wallet" });

    return el("form", {
      class: "w-form",
      onsubmit: async ev => {
        ev.preventDefault();
        err.hidden = true;
        if (!mnemonic.value.trim()) { err.textContent = "Enter the recovery phrase."; err.hidden = false; return; }
        if (!pass.value) { err.textContent = "Choose a wallet password."; err.hidden = false; return; }
        if (pass.value !== passConfirm.value) { err.textContent = "Passwords do not match."; err.hidden = false; return; }
        const chosenPass = pass.value;
        // unchecked → legacy pre-1627 derivation (matches a CLI restore);
        // checked → modern EIP-3.
        const usePre1627 = !modern.checked;
        btn.disabled = true;
        let r;
        try {
          r = await walletPostJson("/wallet/restore", {
            mnemonic: mnemonic.value.trim(),
            mnemonicPass: mnemonicPass.value,
            pass: chosenPass,
            usePre1627KeyDerivation: usePre1627,
          });
        } catch (_) {
          mnemonic.value = "";
          btn.disabled = false;
          err.textContent = "Network error reaching the node."; err.hidden = false; return;
        }
        // Clear the phrase + passwords from the DOM as soon as the request
        // resolves, success or failure.
        mnemonic.value = ""; pass.value = ""; passConfirm.value = ""; mnemonicPass.value = "";
        btn.disabled = false;
        if (r.status === 403) return onAuthLost();
        if (!r.ok) {
          err.textContent = await reasonOf(r, `restore failed (${r.status})`); err.hidden = false; return;
        }
        // Restored; explicitly unlock with the chosen pass.
        let pass2 = chosenPass;
        let u;
        try {
          u = await walletPostJson("/wallet/unlock", { pass: pass2 });
        } catch (_) {
          pass2 = null;
          onboardUnlockFailed($("w-onboard-pane"), err, "Wallet restored but unlock failed (network). Unlock it from the status view.");
          return;
        }
        pass2 = null;
        if (u.status === 403) return onAuthLost();
        if (u.ok) {
          resumeLiveView();
        } else {
          onboardUnlockFailed($("w-onboard-pane"), err, `Wallet restored but unlock failed: ${await reasonOf(u, "")}. Unlock it from the status view.`);
        }
      },
    },
      field("Recovery phrase", mnemonic),
      field("Wallet password", pass),
      field("Confirm password", passConfirm),
      field("Mnemonic passphrase (BIP39, optional)", mnemonicPass),
      el("label", { class: "w-check" }, modern,
        el("span", { text: "Advanced — use modern EIP-3 derivation (leave unchecked to match a CLI restore)." })),
      el("div", { class: "w-warn-text", text: EXT_WARNING }),
      err,
      el("div", { class: "w-row" }, btn),
    );
  }

  /* ── Send payment ───────────────────────────────────────────────────
     {address, value(nanoERG), assets[]} rows → a simple yes/no confirm
     showing the parsed total → POST /wallet/payment/send with the array
     body → surface the returned txId or the typed error. The form is
     built once (sendRendered) so the 5 s poll never wipes a draft; the
     Send button is gated on the unlocked state, so a wallet_locked race
     leaves the draft intact. */

  let sendRendered = false;

  function showSendPanel() {
    if (sendRendered) return;
    buildSendForm();
    sendRendered = true;
  }

  function setSendEnabled(unlocked) {
    const btn = $("w-send-submit");
    const note = $("w-send-locked");
    if (btn) btn.disabled = !unlocked;
    if (note) note.hidden = unlocked;
  }

  function showSendMsg(kind, text) {
    const m = $("w-send-msg");
    if (!m) return;
    m.className = `w-banner ${kind}`;
    m.textContent = text;
    m.hidden = false;
  }

  function buildSendForm() {
    const body = $("w-send-body");
    body.replaceChildren();

    const rows = el("div", { id: "w-send-rows", class: "w-list" }, recipientRow());
    const addBtn = el("button", { class: "w-btn", type: "button", text: "+ recipient",
      onclick: () => rows.append(recipientRow()) });
    const submit = el("button", { id: "w-send-submit", class: "w-btn primary", type: "button",
      text: "Review & send", onclick: onReviewSend });
    const locked = el("div", { id: "w-send-locked", class: "w-muted", hidden: true,
      text: "Unlock the wallet to send." });
    const msg = el("div", { id: "w-send-msg", class: "w-banner", hidden: true });

    body.append(
      rows,
      el("div", { class: "w-row", style: "margin-top:10px" }, addBtn, submit),
      locked,
      msg,
    );
  }

  function recipientRow() {
    const addr = el("input", { class: "w-input w-r-addr", placeholder: "recipient address (9…)", autocomplete: "off", spellcheck: "false" });
    const value = el("input", { class: "w-input w-r-value", placeholder: "amount (ERG)", inputmode: "decimal", autocomplete: "off" });
    const tokens = el("div", { class: "w-tokens w-r-tokens" });
    const addTok = el("button", { class: "w-btn w-btn-sm", type: "button", text: "+ token",
      onclick: () => tokens.append(tokenRow()) });
    const remove = el("button", { class: "w-btn w-btn-sm", type: "button", text: "remove recipient",
      onclick: ev => ev.target.closest(".w-recipient").remove() });

    return el("div", { class: "w-recipient" },
      el("div", { class: "w-row" }, addr, remove),
      el("div", { class: "w-row", style: "margin-top:6px" }, value),
      tokens,
      el("div", { class: "w-row", style: "margin-top:6px" }, addTok),
    );
  }

  function tokenRow() {
    const id = el("input", { class: "w-input w-t-id", placeholder: "tokenId (hex)", autocomplete: "off", spellcheck: "false" });
    const amt = el("input", { class: "w-input w-t-amt", placeholder: "amount", inputmode: "numeric", autocomplete: "off" });
    const rm = el("button", { class: "w-btn w-btn-sm", type: "button", text: "×",
      onclick: ev => ev.target.closest(".w-token").remove() });
    return el("div", { class: "w-token w-row" }, id, amt, rm);
  }

  // Parse the recipient rows into the /wallet/payment/send body, or return
  // { error } on the first client-side validation failure.
  function collectRequests() {
    const recipients = Array.from(document.querySelectorAll("#w-send-rows .w-recipient"));
    if (!recipients.length) return { error: "Add at least one recipient." };
    const requests = [];
    let totalNano = 0;
    for (const [i, row] of recipients.entries()) {
      const address = row.querySelector(".w-r-addr").value.trim();
      const ergStr = row.querySelector(".w-r-value").value.trim();
      if (!address) return { error: `Recipient ${i + 1}: address is required.` };
      const erg = Number(ergStr);
      if (!ergStr || !Number.isFinite(erg) || erg <= 0) {
        return { error: `Recipient ${i + 1}: enter an amount greater than 0.` };
      }
      const value = Math.round(erg * 1e9);
      if (!Number.isSafeInteger(value)) return { error: `Recipient ${i + 1}: amount is too large.` };
      totalNano += value;

      const assets = [];
      for (const [j, t] of Array.from(row.querySelectorAll(".w-token")).entries()) {
        const tokenId = t.querySelector(".w-t-id").value.trim();
        const amtStr = t.querySelector(".w-t-amt").value.trim();
        if (!tokenId && !amtStr) continue; // blank token row → skip
        if (!tokenId) return { error: `Recipient ${i + 1}, token ${j + 1}: tokenId is required.` };
        const amount = Number(amtStr);
        if (!Number.isInteger(amount) || amount <= 0) {
          return { error: `Recipient ${i + 1}, token ${j + 1}: amount must be a positive integer.` };
        }
        assets.push({ tokenId, amount });
      }
      requests.push({ address, value, assets });
    }
    return { requests, totalNano };
  }

  function onReviewSend() {
    $("w-send-msg").hidden = true;
    const { requests, totalNano, error } = collectRequests();
    if (error) { showSendMsg("err", error); return; }
    showConfirmModal(requests, totalNano);
  }

  function showConfirmModal(requests, totalNano) {
    const overlay = el("div", { class: "w-modal-overlay" });
    const close = () => overlay.remove();
    overlay.addEventListener("click", ev => { if (ev.target === overlay) close(); });

    const lines = el("div", { class: "kv", style: "margin:10px 0" });
    for (const req of requests) {
      const k = el("div", { class: "k hash", text: trunc(req.address) });
      k.title = req.address;
      const tokNote = req.assets.length ? ` + ${req.assets.length} token${req.assets.length > 1 ? "s" : ""}` : "";
      lines.append(k, el("div", { class: "v", text: `${fmtErg(req.value)} ERG${tokNote}` }));
    }

    const confirm = el("button", { class: "w-btn primary", type: "button", text: "Confirm send",
      onclick: () => { close(); doSend(requests); } });
    const cancel = el("button", { class: "w-btn", type: "button", text: "Cancel", onclick: close });

    overlay.append(el("div", { class: "w-modal" },
      el("div", { class: "w-modal-title", text: "Confirm payment" }),
      el("div", { class: "w-muted",
        text: `${requests.length} recipient${requests.length > 1 ? "s" : ""} · total ${fmtErg(totalNano)} ERG (plus network fee)` }),
      lines,
      el("div", { class: "w-row", style: "justify-content:flex-end;margin-top:6px" }, cancel, confirm),
    ));
    document.body.append(overlay);
  }

  async function doSend(requests) {
    const btn = $("w-send-submit");
    btn.disabled = true;
    showSendMsg("info", "Building, signing and submitting — this can take a few seconds…");
    let r;
    try {
      r = await walletPostJson("/wallet/payment/send", requests);
    } catch (_) {
      btn.disabled = false;
      showSendMsg("err", "Network error reaching the node.");
      return;
    }
    btn.disabled = false;
    if (r.status === 403) return onAuthLost();
    if (r.ok) {
      const { txId } = await r.json();
      showSendMsg("info", `Submitted. txId: ${txId}`);
    } else {
      const reason = await reasonOf(r, `send failed (${r.status})`);
      showSendMsg("err", reason === "wallet_locked"
        ? "Wallet is locked — unlock it above and try again. Your draft is preserved."
        : `Send failed: ${reason}`);
    }
  }

  /* ── Keys: derive next key + change address ─────────────────────────
     deriveNextKey is GET (no body — the server picks the next index);
     updateChangeAddress POSTs { address }. The change-address selector is
     repopulated from the addresses list on each refresh, preserving the
     operator's current selection. Both need an unlocked wallet, so the
     panel shows only while unlocked. */

  let keysRendered = false;

  function showKeysPanel() {
    $("w-keys-panel").hidden = false;
    if (keysRendered) return;
    buildKeysForm();
    keysRendered = true;
  }

  function showKeyMsg(id, kind, text) {
    const m = $(id);
    if (!m) return;
    m.className = `w-banner ${kind}`;
    m.textContent = text;
    m.hidden = false;
  }

  function buildKeysForm() {
    const body = $("w-keys-body");
    body.replaceChildren();

    const deriveBtn = el("button", { id: "w-derive-btn", class: "w-btn", type: "button", text: "Derive next key", onclick: deriveNextKey });
    const deriveMsg = el("div", { id: "w-derive-msg", class: "w-banner", hidden: true });

    const select = el("select", { id: "w-change-select", class: "w-input" });
    const changeBtn = el("button", { id: "w-change-btn", class: "w-btn", type: "button", text: "Set change address", onclick: updateChangeAddress });
    const changeMsg = el("div", { id: "w-change-msg", class: "w-banner", hidden: true });

    body.append(
      el("div", { class: "w-label", text: "Derive a new address" }),
      el("div", { class: "w-row" }, deriveBtn),
      deriveMsg,
      el("div", { class: "w-label", style: "margin-top:14px", text: "Change address (must be a tracked address)" }),
      el("div", { class: "w-row" }, select, changeBtn),
      changeMsg,
    );
  }

  async function deriveNextKey() {
    const btn = $("w-derive-btn");
    btn.disabled = true;
    let r;
    try {
      r = await walletFetch("/wallet/deriveNextKey");
    } catch (_) {
      btn.disabled = false;
      showKeyMsg("w-derive-msg", "err", "Network error reaching the node.");
      return;
    }
    btn.disabled = false;
    if (r.status === 403) return onAuthLost();
    if (r.ok) {
      const d = await r.json(); // { derivationPath, address }
      showKeyMsg("w-derive-msg", "info", `Derived ${d.derivationPath} → ${d.address}`);
      refreshAddresses(); // reflect the new entry + repopulate the selector
    } else {
      showKeyMsg("w-derive-msg", "err", await reasonOf(r, `derive failed (${r.status})`));
    }
  }

  async function updateChangeAddress() {
    const address = $("w-change-select").value;
    if (!address) {
      showKeyMsg("w-change-msg", "err", "Select an address first (derive one if the list is empty).");
      return;
    }
    const btn = $("w-change-btn");
    btn.disabled = true;
    let r;
    try {
      r = await walletPostJson("/wallet/updateChangeAddress", { address });
    } catch (_) {
      btn.disabled = false;
      showKeyMsg("w-change-msg", "err", "Network error reaching the node.");
      return;
    }
    btn.disabled = false;
    if (r.status === 403) return onAuthLost();
    if (r.ok) {
      showKeyMsg("w-change-msg", "info", "Change address updated.");
      refresh();
    } else {
      // change_address_untracked surfaces here for an address outside the
      // wallet's tracked-pubkey set (strict mode).
      showKeyMsg("w-change-msg", "err", await reasonOf(r, `update failed (${r.status})`));
    }
  }

  function populateChangeSelect(list) {
    const sel = $("w-change-select");
    if (!sel) return;
    const prev = sel.value;
    sel.replaceChildren();
    for (const addr of list) {
      sel.append(el("option", { value: addr, text: trunc(addr, 16, 10) }));
    }
    if (list.includes(prev)) sel.value = prev;
  }

  /* ── Refresh + polling ──────────────────────────────────────────── */
  async function refresh() {
    let r;
    try {
      r = await walletFetch("/wallet/status");
    } catch (_) {
      $("w-status-body").replaceChildren(el("div", { class: "w-muted", text: "Node unreachable — retrying…" }));
      return;
    }
    if (r.status === 403) return onAuthLost();
    if (!r.ok) {
      $("w-status-body").replaceChildren(
        el("div", { class: "w-muted", text: `/wallet/status returned ${r.status} (${await reasonOf(r, "error")}).` }),
      );
      return;
    }
    const s = await r.json();
    renderScanBanner(s);
    if (!s.isInitialized) {
      // Onboarding never polls: a background tick must not navigate away
      // from a half-typed restore phrase or the once-shown init mnemonic
      // gate. The flow resumes live polling explicitly after unlock.
      stopPolling();
      setOnboarding(true);
      showOnboard();
      return;
    }
    setOnboarding(false);
    ensurePolling();
    renderStatusPanel(s);
    showSendPanel();
    setSendEnabled(s.isUnlocked);
    if (s.isUnlocked) {
      refreshBalances();
      refreshAddresses();
      showKeysPanel();
    } else {
      readsLockedNote("w-balances-body", "balances");
      readsLockedNote("w-addresses-body", "addresses");
      $("w-balances-right").textContent = "";
      $("w-addresses-right").textContent = "";
      $("w-keys-panel").hidden = true;
    }
  }

  let pollId = null;
  function startPolling() {
    stopPolling();
    pollId = setInterval(() => {
      if (document.visibilityState !== "hidden") refresh();
    }, 5000);
  }
  function stopPolling() {
    if (pollId != null) {
      clearInterval(pollId);
      pollId = null;
    }
  }
  // Start polling only if it isn't already running. refresh() owns the
  // decision: it polls in the live (initialized) view and suspends polling
  // on the onboarding screen.
  function ensurePolling() {
    if (pollId == null) startPolling();
  }

  function enterApp() {
    $("wallet-auth").hidden = true;
    $("wallet-app").hidden = false;
    $("wallet-logout").hidden = false;
    refresh();
  }

  function init() {
    $("wallet-auth-form").addEventListener("submit", onAuthSubmit);
    $("wallet-logout").addEventListener("click", logout);
    if (getKey()) {
      enterApp();
    } else {
      showAuthPrompt();
    }
  }

  return { init };
})();

document.addEventListener("DOMContentLoaded", Wallet.init);
