# Unified Node Operator UI — Design

Date: 2026-06-16
Branch: `feat/unified-node-ui` (stacked on `feat/votes-history`, targets `main`)
Surface: `ergo-api/web/` (vanilla JS, no build step) + `ergo-api/src/` serving layer.

> Revision 2 — incorporates the codex design review (4 blockers + 6 should-fixes),
> all verified against the code. Key corrections from r1: `/wallet/status` IS a
> universal api_key probe (always-mounted, gated), so verification is active not
> just opportunistic; folding the wallet into `/` changes the mnemonic threat
> model and the CSP scope (an existing test asserts `/` has no CSP); shared
> components must be added *additively* before the wallet forks are deleted.

## Problem

The node's web UI has drifted into three surfaces with one-and-a-half design
systems:

1. **Dashboard SPA** (`index.html` + `js/*`) — the de-facto design system:
   `tokens.css` + `components.css` + `dashboard.css`. Hash router, sections
   Overview / Peers / Mempool / Voting. API key set only in the ⚙ Settings
   dialog (`js/settings.js`), `sessionStorage['ergo.apikey']`, injected
   per-request by `js/api-client.js`.
2. **Wallet** (`wallet/index.html` + `wallet/wallet.js`) — a *parallel fork*:
   loads `tokens.css` + `components.css` but **not** `dashboard.css`, and
   re-declares the shell + `.panel` + button + input + tab systems in
   `wallet.css` with divergent names (`.w-btn` vs `.btn`, `.panel-head` vs
   `.panel__head`, `.active` vs `aria-selected`). Stores the key under a
   **different** slot `sessionStorage['ergo_api_key']` (`wallet.js:49`).
3. **Swagger ×2** (`swagger.html` Scala-parity, `swagger-native.html` Rust
   native) — off the design system (hardcoded hex, own font stack, duplicated
   banner `<style>`), not theme-aware. Both already read `ergo.apikey` to
   preauthorize (`swagger.html:56`, `swagger-native.html:50`).

### Concrete drift (file:line)

- **High — wallet fork:** `wallet.css:6-68` re-declares `.app/.side/.main`
  (drifted: `min-height` vs `height`, different `.main` max-width/padding);
  `.panel` defined twice (`wallet.css:81` vs `components.css:89`);
  `.w-btn*` (`wallet.css:159`) duplicates `.btn` (`components.css:10`).
- **High — ERG precision:** `erg()` is BigInt-exact (`format.js:4`); wallet
  `fmtErg` is lossy float `(n/1e9).toFixed(4)` (`wallet.js:41`). Worse, send
  *parsing* is float-based `Math.round(erg*1e9)` (`wallet.js:701`) and token
  amounts use unsafe `Number(amtStr)` (`wallet.js:711`) — silent corruption for
  values > 2^53 (ERG total supply ≈ 9.77e16 nanoErg ≫ `MAX_SAFE_INTEGER`).
- **High — split key storage:** `ergo.apikey` (`settings.js:2`) vs
  `ergo_api_key` (`wallet.js:49`).
- **Medium:** two table systems (`.dtable` responsive vs voting `.vtable` with
  no mobile reflow, `dashboard.css:398`); wallet hardcodes `theme-dark`
  (`wallet/index.html:2`); two modal patterns (native `<dialog>` vs hand-rolled
  overlay, no focus-trap/Escape/aria, `wallet.js:729`); voting auth reactive-only
  (`voting.js:152`); focus outline `--accent` vs `--blue` (`dashboard.css:441`).
- **Low:** dead tokens `--topbar-h/--footer-h/--grid-line`, never-read
  `--fs-hero`; duplicated `span()`/`num`/`trunc`; three border tokens for the
  row-divider role; `.copy` not keyboard-focusable; `getJson` swallows 403 as
  null (`api-client.js:5`).

## Goals / Non-goals

Goals: one unified SPA, one design system, one Authorize control; fold the
wallet into the SPA preserving its funds-safety guards.

Non-goals (YAGNI): no framework/build step; **no REST API surface changes**
(client consolidation + one redirect route only — so amount wire format stays a
JSON number, see §B.9); **Scala `swagger.html` untouched**; no new operator
features beyond Authorize.

## Decisions (locked with operator)

1. Full unification; Scala swagger untouched.
2. One SPA with a *proper section lifecycle*; wallet folds in as a section but
   stays its own guarded module.
3. Authorize: shell lock chip **+** Overview prompt when unauthorized; key out of
   ⚙ Settings; one storage slot; **active verify on entry via `GET
   /wallet/status` + opportunistic re-verify**; gated actions show disabled
   "Authorize first".
4. The two wallet secrets are never conflated: shell Authorize = HTTP `api_key`;
   the wallet section keeps the server-side **unlock (password)** as its own step.

## Design

### A. Shell + section lifecycle  *(codex blocker #1)*

The scheduler cannot police "don't rebuild" from outside, because sections own
their DOM (`overview.renderBody()`, `table.draw()` both `replaceChildren`). So
the contract makes the **section** responsible, with the scheduler cooperating:

- **`mount(el)`** — build DOM once; idempotent (guard against double-mount).
- **`onShow()` / `onHide()`** — section activated/deactivated by the router.
  `onHide()` MUST run the section's teardown incl. secret-scrub (see §D).
- **`onFast(data)` / `onSlow()`** — live ticks **only for the visible section**.
  The scheduler:
  - skips `onFast/onSlow` entirely when `document.visibilityState==='hidden'`
    (already true) **and** when the section is not the active one;
  - serializes `onSlow` per section with an **in-flight guard** (no overlapping
    runs if a slow fetch outlives the 4 s tick);
  - tags each `onSlow` run with a monotonic **request token**; a late response
    whose token is stale is dropped (no write-after-unmount, no torn paint).
- **`isBusy()`** — the section returns `true` while it holds in-flight user input
  (wallet send/mnemonic/unlock, voting edits). The scheduler **does not call the
  section's rebuild path while busy**; instead the section exposes a lightweight
  `refreshCells()`-style patch the scheduler may call to update read-only values
  without touching inputs (voting already has this; overview/wallet gain it).
- **`teardown()`** — drop timers/listeners on unmount.

Router (`router.js`) calls `onHide` on the outgoing section then `onShow` on the
incoming one. Overview stops the wasteful full `replaceChildren` every 4 s
(`overview.js:315`) and adopts patch-on-update.

### B. Shared component layer (added additively, forks deleted LAST)  *(blocker #4)*

Consolidate into `components.css`. **New shared classes are added first
alongside the existing forks; the wallet/page-local duplicates are deleted only
in the final wallet-migration step (§ build seq 6), so `/wallet/ui` keeps
working throughout.**

- **Buttons:** one `.btn` (+`--primary/--danger/--ghost/--sm`); wallet `.w-btn*`
  deleted after migration; voting "Clear all" → `--danger`.
- **Panels:** one `.panel`/`.panel__head`/`.panel__body` (+`__title`,`__dot`,
  `__right` to absorb the wallet's panel-head needs); wallet hyphenated `.panel-*`
  + duplicate `.panel` deleted after migration.
- **Inputs:** one `.input`/`.textarea` (settings, voting, wallet, authorize).
- **Tabs:** one `.tabs/.tab` on `aria-selected`; wallet onboarding adopts it.
- **Tables (codex #8 — fallback chosen up front):** do **NOT** force voting onto
  the card-row `.dtable` — its `draw()` `replaceChildren`s on every update, which
  would clobber the operator's in-progress vote inputs and break `refreshCells`.
  Instead add ONE shared **responsive semantic-table** style
  (`.table`/`.table__num`/responsive `<760px` treatment via `data-label` on
  `<td>`) used by voting, with **stable input nodes** preserved and proper
  `<th scope>` / `aria-sort` (voting is non-sorting, so no sort glyphs). `.dtable`
  stays the card-row table for peers/mempool. Two table *components* with one
  shared token/skin vocabulary — by design, not drift.
- **Status:** keep inline `.pill`; add ONE block-level `.banner`
  (`--ok/--err/--warn/--info`) for wallet errors, voting status line, authorize
  prompt, scan-invalidated. Voting `setStatus` toggles a class + `aria-live`
  instead of inline `style.color`.
- **Modals:** native `<dialog>` everywhere; wallet send-confirm migrates off the
  hand-rolled overlay (gains focus-trap/Escape/`role=dialog`).
- **KV rows:** one shared `.kv` (merge `.ov-kv` + wallet `.kv`).
- **Copy:** one `.copy`, keyboard-focusable (`role=button`,`tabindex=0`,
  Enter/Space, focus style); wallet gains copy on address/txid/change-address.
- **Format helpers:** wallet imports `js/format.js` — kills lossy `fmtErg` +
  duplicate `num`/`trunc`.
- **§B.9 — exact amount parsing (codex #9):** add a `nanoErgFromDecimal(str)`
  helper to `format.js` that parses a decimal-ERG **string** to a BigInt nanoErg
  (no float). Wallet send: parse each recipient ERG with it; token amounts parsed
  as BigInt from string. Because the wire format is a JSON number (non-goal to
  change), **reject** any value or token amount that exceeds
  `Number.MAX_SAFE_INTEGER` with a clear operator error (today's float path
  silently corrupts these). Confirm-modal total summed in BigInt.
- **Tokens:** drop dead `--topbar-h/--footer-h/--grid-line`; resolve `--fs-hero`;
  add `.ov-big`'s off-scale 18px to the scale; standardize the row-divider token;
  standardize focus outline to `--accent` (fix `.vt-input` `--blue`); tokenize
  the modal backdrop alpha.

### C. Authorize subsystem  *(codex #5, #6, #7)*

- **Single storage slot** `ergo.apikey`. **Legacy migration is a MOVE (codex
  #6):** on load, if `ergo_api_key` exists, copy → `ergo.apikey` (only if unset)
  then **`removeItem('ergo_api_key')`**; clearing the key removes both slots, so
  the legacy value can never resurrect.
- **Verification = active probe (codex #5):** `/wallet/status` is always mounted
  and api_key-gated (server.rs:1130), returning 200 (valid key) / 403 (bad key)
  regardless of wallet config. On key entry, probe it:
  - 200 → **Authorized** (verified);
  - 403 → **Invalid key**;
  - network/other → **Key set (unverified)** — never claim "Authorized" from
    storage alone.
  Plus **opportunistic re-verify**: any later gated call returning 403 with a key
  set flips the chip to *Invalid key*; any 200 confirms *Authorized*.
- **api-client compat (codex #7):** keep every `api.*` method's current
  data-or-null / `{ok,status,detail}` shape (callers unchanged). Add a low-level
  status-aware wrapper inside `api-client.js` that, as a **side effect**, emits an
  auth-state event (`ok` / `forbidden`) to a tiny pub-sub the chip + Overview
  prompt + gated actions subscribe to. No caller signatures change.
- **Shell lock chip** in the sidebar foot near the connection status. States:
  *Authorize* / *checking…* / *Authorized* / *Invalid key* / *Key set
  (unverified)*. Click → `<dialog>` (shared input + buttons) to set/clear.
- **Overview prompt:** unauthorized → a `.banner` "Authorize to unlock operator
  controls" with an inline Authorize button; removed once authorized.
- **Gated actions:** voting Save/Clear + wallet ops render disabled "Authorize
  first" when no key; re-enable on authorize.
- **Settings dialog** loses the `api_key` field → pure prefs (theme/density/
  explorer).

### D. Wallet as a section  *(codex blocker #2)*

- `wallet/index.html` markup → a `#wallet` `<section>` in `index.html`;
  `wallet/wallet.js` → `js/wallet.js` on the new lifecycle, using shared
  components + `js/api-client.js` (extended with wallet endpoints) + `format.js`.
- **Layered secrets:** shell Authorize = `api_key`; wallet section = server-side
  **unlock (password)**. States: no key → authorize prompt; key but locked →
  unlock; unlocked → panels.
- **Threat-model mitigation (codex blocker #2).** Today the wallet is a separate
  document, so navigating to the dashboard fully unloads it — wiping mnemonic /
  passwords / draft from DOM and (mostly) heap. As an in-SPA section, navigating
  away merely *hides* it, leaving secrets in hidden DOM. Required mitigations:
  - `wallet.onHide()` **scrubs sensitive DOM**: clears any mnemonic `<pre>`, all
    password/passphrase inputs, and resets the memoised onboarding/unlock/send
    panes (set their `*Rendered=false` and `replaceChildren`).
  - **Nav-guard while the mnemonic gate is on screen** (phrase shown, not yet
    acknowledged): intercept section navigation (and `beforeunload`) with a
    confirm — leaving discards the only copy. Mirrors the existing once-shown
    semantics, now that accidental in-SPA nav is easy.
  - Honesty: JS-heap residue (a `mnemonic` string still referenced) can't be
    guaranteed gone without a full unload; we null references after use (already
    done at `wallet.js:504,515`) and scrub the DOM — best-effort, same posture as
    the existing `no-store` bfcache note.
- Preserve: poll-suspend-during-mnemonic, don't-clobber-input (via `isBusy()`),
  the write-down gate. Send-confirm → `<dialog>`.
- **Fix two latent issues:** optimistic send allows resubmitting the same draft
  (`wallet.js:770` — reset/disable form on submit); UI "logout" doesn't lock
  server-side (`wallet.js:154` — offer to `POST /wallet/lock` on logout).
- Theme/density now apply to the wallet automatically (it's in the shell).

### E. Native Swagger + a11y

- Scala `swagger.html`: untouched.
- `swagger-native.html`: theme-aware (load `/tokens.css`, honor the app theme via
  a small inline bootstrap that reads `ergo.prefs`), dedupe the banner `<style>`,
  use the shared `.banner`, add a "set api_key on the dashboard to pre-authorize"
  hint. Swagger-UI core CSS stays (CDN, SRI-pinned) → so `/swagger/native` is
  **excluded from the strict CSP** in §F.
- a11y ride-along: `aria-sort` on sortable `.dtable` headers (`table.js:34`),
  `role=progressbar`+`aria-valuenow` on gauges, `aria-live` on status/banners,
  input labels.

### F. Rust serving + security-header changes  *(codex blockers #3, #10)*

- **web.rs:** add `pub const JS_WALLET = include_str!("../web/js/wallet.js")`.
  After migration, remove the `WALLET_UI_INDEX_HTML` / `WALLET_UI_JS` /
  `WALLET_CSS` includes (old files deleted).
- **server.rs routes:** add `/js/wallet.js`; replace the `/wallet/ui*` static
  group with a **redirect** `/wallet/ui` → `/#wallet` (301/308) for bookmarks
  (`/wallet/ui/index.html`, `/wallet/ui/wallet.js` redirect or 404 — they no
  longer exist).
- **Extend the security-header layer to the SPA root (codex #3).** The wallet now
  lives at `/`, so `/` + every SPA asset (`/`, `/index.html` if any, the CSS, the
  `/js/*` modules, the font) must carry the wallet-grade headers (CSP
  `default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline';
  script-src 'self'`, `Cache-Control: no-store…`, `Pragma`, `Referrer-Policy:
  no-referrer`). Implement by grouping the static-SPA routes under the existing
  `from_fn(wallet_ui_security_headers)` layer (renamed `spa_security_headers`).
  **Exclude** `/swagger`, `/swagger/native`, `/api-docs/*`, `/api/v1/*`,
  `/metrics` (swagger needs the CDN; CSP on JSON is noise). Verified safe: the
  font is self-hosted (web.rs:34), so `default-src 'self'` does not break it —
  correct the stale "CDN-hosted web font" comment at server.rs:1213.
- **Tests (codex #10):**
  - Rewrite `wallet_ui_headers.rs::dashboard_root_does_not_carry_wallet_csp` →
    `dashboard_root_carries_spa_security_headers` (now `/` SHOULD carry CSP +
    no-store + no-referrer), and assert `/js/*.js`, the CSS, and `/js/wallet.js`
    carry them too. Keep an assertion that `/swagger/native` does **NOT** carry
    the strict CSP.
  - Update `wallet_ui_auth_scope.rs`: `/wallet/ui` now redirects (assert 3xx →
    `/#wallet`) instead of serving the page; the public-without-key property moves
    to `/` (already public). `/wallet/*` JSON stays gated (unchanged).
  - Run the full Rust gate (`cargo fmt --all -- --check`; `cargo clippy
    --workspace --all-targets --all-features -- -D warnings`; `cargo test
    --workspace`) — these tests live in `ergo-api/tests/`.

## Build sequence (additive-first; deletions last)

1. **Add** shared components to `components.css` additively (`.input`, `.banner`,
   `.table`, `.kv`, `__title/__dot/__right`, `.copy` focus) + token cleanup —
   without removing any wallet/page forks yet.
2. Section lifecycle (`app.js`, `router.js`): `mount/onShow/onHide/onFast/onSlow/
   isBusy/teardown`, in-flight + request-token guards.
3. Authorize subsystem (`js/auth.js`, `api-client.js` low-level wrapper +
   events, settings split, shell chip, Overview prompt, gated states,
   `/wallet/status` probe, legacy-key move).
4. Migrate dashboard sections to shared components (overview patch-on-update;
   voting → shared `.table` + `.banner` + disabled gating; peers/mempool a11y).
5. Build the `#wallet` section (`js/wallet.js`) using shared components +
   `format.js` (incl. `nanoErgFromDecimal`) + lifecycle scrub/nav-guard;
   **extend the security-header layer to `/` + SPA assets** and add the
   `/js/wallet.js` route.
6. Flip `/wallet/ui` → redirect; **delete** old `wallet/index.html`,
   `wallet/wallet.js`, `wallet.css`, and their `web.rs` includes; **delete** the
   `.w-*` / `.panel-*` / duplicate-`.panel` CSS. Update Rust tests (§F).
7. Native swagger theming + dedupe.
8. a11y pass.

## Testing / verification

- Vanilla/no-build: extend `?selftest` console-assert blocks for pure helpers,
  incl. new `nanoErgFromDecimal` cases (exactness, sub-unit, > MAX_SAFE reject).
- Rust: the rewritten `wallet_ui_headers.rs` + `wallet_ui_auth_scope.rs` and the
  full workspace gate.
- Manual plan: authorize flow incl. **legacy-key move** (set `ergo_api_key`,
  load, confirm it moved + old slot gone) and the 200/403/unverified states;
  gated-action disabled states; wallet unlock/send/mnemonic with poll live;
  **secret scrub** (open mnemonic gate → navigate away → return → phrase gone) +
  nav-guard confirm; exact-amount reject for > MAX_SAFE; theme switch across all
  sections incl. wallet + native swagger; voting-table mobile reflow; settings no
  longer holds the key.

## Risks / open calls

1. JS-heap secret residue after in-SPA nav is best-effort only (DOM scrubbed,
   references nulled) — documented, matches existing `no-store` posture. If the
   operator deems this insufficient, the fallback is to keep the wallet a separate
   document sharing the design system (the r1 "shared shell, separate page"
   option) — flagged, not chosen.
2. Wallet ~970 lines load with the SPA always (no lazy-load without a build step)
   — trivial when locally served.
3. Native-swagger theming is chrome-only (banner + page bg + font); Swagger-UI's
   own widget theming is out of scope.
4. Stacking on unmerged `feat/votes-history` — rebase coupling if it changes.
