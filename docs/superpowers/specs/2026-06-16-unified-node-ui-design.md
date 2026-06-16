# Unified Node Operator UI — Design

Date: 2026-06-16
Branch: `feat/unified-node-ui` (stacked on `feat/votes-history`, targets `main`)
Surface: `ergo-api/web/` (vanilla JS, no build step)

## Problem

The node's web UI has drifted into three surfaces with one-and-a-half design
systems:

1. **Dashboard SPA** (`index.html` + `js/*`) — the de-facto design system:
   `tokens.css` + `components.css` + `dashboard.css`. Hash router, sections
   Overview / Peers / Mempool / Voting. API key set only in the ⚙ Settings
   dialog (`js/settings.js`), stored `sessionStorage['ergo.apikey']`, injected
   per-request by `js/api-client.js`.
2. **Wallet** (`wallet/index.html` + `wallet/wallet.js`) — a *parallel fork*:
   loads `tokens.css` + `components.css` but **not** `dashboard.css`, and
   re-declares the whole shell + `.panel` + button + input + tab systems in
   `wallet.css` with divergent names (`.w-btn` vs `.btn`, `.panel-head` vs
   `.panel__head`, `.active` vs `aria-selected`). Stores the key under a
   **different** slot `sessionStorage['ergo_api_key']` (`wallet.js:49`).
3. **Swagger ×2** (`swagger.html` Scala-parity, `swagger-native.html` Rust
   native) — off the design system entirely (hardcoded hex, own font stack,
   duplicated banner `<style>`), not theme-aware.

### Concrete drift found in the audit (file:line)

- **High — wallet fork:** `wallet.css:6-68` re-declares `.app/.side/.main`
  (already drifted: `min-height` vs `height`, different `.main` max-width /
  padding token); `.panel` defined twice (`wallet.css:81-87` vs
  `components.css:89-96`); `.w-btn*` (`wallet.css:159-199`) duplicates `.btn`
  (`components.css:10-45`).
- **High — ERG precision bug:** dashboard `erg()` is BigInt-exact
  (`format.js:4-10`); wallet `fmtErg` is lossy float `(n/1e9).toFixed(4)`
  (`wallet.js:41`). Same value renders differently across surfaces.
- **High — split key storage:** `ergo.apikey` (`settings.js:2`) vs
  `ergo_api_key` (`wallet.js:49`) — a key entered on the dashboard does not
  authorize the wallet, and vice-versa.
- **Medium:** two table systems (`.dtable` responsive vs voting's `.vtable`
  with no mobile reflow, `dashboard.css:398-430`); wallet hardcodes
  `theme-dark` and ignores theme/density prefs (`wallet/index.html:2`); two
  modal patterns (native `<dialog>` for settings vs hand-rolled overlay for
  wallet send-confirm, no focus-trap/Escape/aria); voting auth is
  reactive-only (Save never disabled, `voting.js:152-155`); focus outline color
  inconsistent (`--accent` vs `--blue` on `.vt-input`, `dashboard.css:441-444`).
- **Low (cleanup):** dead tokens `--topbar-h/--footer-h/--grid-line` and a
  never-read `--fs-hero`; duplicated `span()` (peers.js + mempool.js) and
  `num`/`trunc` (wallet); three different border tokens for the row-divider
  role; `.copy` not keyboard-focusable (`components.css:126-133`); api-client
  swallows 403 indistinguishably from a down node (`api-client.js:5-16`).

## Goals

- One unified SPA, one design system, one Authorize control.
- A first-class **Authorize** affordance (the headline ask): a persistent shell
  lock chip + an Overview prompt when unauthorized; the `api_key` moves out of
  ⚙ Settings into this dedicated control.
- Fold the wallet into the SPA as a section sharing the shell, components, state
  and styling — while preserving its funds-safety guards.

## Non-goals (YAGNI)

- No framework / build step — stays vanilla, no-build.
- No REST API surface changes (client consolidation + one redirect route only).
- **Scala-compat `swagger.html` is left untouched** (operator instruction).
- No new operator features beyond Authorize (no new dashboards/metrics).

## Decisions (locked with the operator)

1. **Scope:** full unification; Scala swagger untouched.
2. **Architecture:** one unified SPA with a *proper section lifecycle*; the
   wallet folds in as a section but stays its own guarded module.
3. **Authorize:** shell lock chip **+** Overview prompt when unauthorized; key
   pulled out of ⚙ Settings; one storage slot; **store + opportunistic verify**;
   gated actions show a disabled "Authorize first" state.
4. **Two distinct wallet secrets** are never conflated: shell Authorize = the
   HTTP `api_key`; the wallet section keeps the server-side **unlock (password)**
   as its own step.

## Design

### A. Shell + section lifecycle

- `index.html` remains the single shell (sidebar + one `<main>` section host the
  router swaps). **Wallet joins the nav** as `#wallet` (drop the external `↗`).
  Keep `/wallet/ui` → `#wallet` redirect for bookmarks.
- Grow the section contract from `mount/onFast/onSlow` to:
  - `mount(el)` — build DOM once.
  - `onShow()` / `onHide()` — activate/deactivate section-specific work.
  - `onFast(data)` / `onSlow()` — live ticks while visible (unchanged cadence:
    1 s fast, 4 s slow, both visibility-gated).
  - **`isBusy()`** — sections with in-flight user input (wallet send/mnemonic,
    voting edits) signal "patch, do not rebuild"; the scheduler then does a
    patch-only refresh, never `replaceChildren`.
  - `teardown()` — optional cleanup on unmount.
- Router (`router.js`) calls `onHide` on the outgoing section and `onShow` on the
  incoming one. Side benefit: Overview stops the wasteful full
  `replaceChildren` every 4 s (`overview.js:315`) and moves to patch-on-update.

### B. Shared component layer (delete the forks)

Consolidate into `components.css`; remove wallet/page duplicates:

- **Buttons:** one `.btn` (+`--primary/--danger/--ghost/--sm`); delete
  `.w-btn*`; voting "Clear all" becomes `--danger`.
- **Panels:** one `.panel`/`.panel__head`/`.panel__body` (+`__title`,`__dot`,
  `__right`); delete the wallet hyphenated `.panel-*` and its duplicate `.panel`.
- **Inputs:** one `.input`/`.textarea` shared by settings, voting, wallet,
  authorize; delete `.w-input/.w-textarea` and bespoke `.vt-input` styling
  (keep number-input semantics).
- **Tabs:** one `.tabs/.tab` keyed on `aria-selected`; wallet onboarding tabs
  adopt it (drop `.w-tab.active`).
- **Tables:** one responsive `.dtable`; migrate voting's `.vtable` onto it so it
  gains the <760px card reflow it lacks. (Trade-off accepted: the voting matrix
  stops being a semantic `<table>`. If codex argues semantics matter more than
  one-table-system, fall back to: keep a single shared *semantic-table* style in
  `components.css` with a responsive treatment, used by voting only.)
- **Status / notifications:** keep inline `.pill`; add ONE block-level `.banner`
  (`--ok/--err/--warn/--info`) for wallet errors, the voting status line, the
  authorize prompt, and scan-invalidated. Voting `setStatus` stops setting
  inline `style.color` and toggles a class + `aria-live`.
- **Modals:** native `<dialog>` everywhere; wallet send-confirm migrates off its
  hand-rolled overlay (gains focus-trap / Escape / `role=dialog`).
- **KV rows:** one shared `.kv` (merge `.ov-kv` + wallet `.kv`).
- **Copy affordance:** one `.copy`, made keyboard-focusable (`role=button`,
  `tabindex=0`, Enter/Space, focus style); wallet gains copy on
  address/txid/change-address.
- **Format helpers:** wallet imports `js/format.js` — **kills the lossy float
  `fmtErg`** (correctness fix) and the duplicate `num`/`trunc`.
- **Cell-grid primitive:** one `.cell-grid` for the kpi/comp/mp-cap
  "1px-gap-over-`--bd2`" pattern.
- **Token cleanup:** drop dead `--topbar-h/--footer-h/--grid-line`; resolve
  `--fs-hero` (use or remove); add `.ov-big`'s off-scale 18px to the scale;
  standardize the row-divider border token; standardize focus outline to
  `--accent` (fix `.vt-input` `--blue`); tokenize the modal backdrop alpha.

### C. Authorize subsystem

- **Single storage slot** `ergo.apikey`; wallet drops `ergo_api_key`. One-time
  migration on load: if legacy `ergo_api_key` exists and `ergo.apikey` does not,
  copy it over (no surprise logout).
- **Shell lock chip** in the sidebar foot near the connection status. States:
  *Authorize* (open lock) / *Authorized* (closed) / *Invalid key* (warn). Click
  → `<dialog>` with a password field (set/clear) built from the shared
  input+buttons.
- **Overview prompt:** when unauthorized, Overview shows a `.banner`
  "Authorize to unlock operator controls" with an inline Authorize button (same
  dialog); removed once authorized.
- **Opportunistic verify:** `api-client` starts distinguishing 403 from other
  failures (today `getJson` swallows all to null, `api-client.js:5-16`). A
  definitive 200 on a gated call with a key set → *Authorized*; a 403 with a key
  set → *Invalid key*. A small pub/sub (or callback) lets the chip + Overview
  prompt + gated actions react. No universal verify-on-entry probe exists (gated
  GETs are all wallet/mining/scan, none guaranteed by node config), so
  verification is opportunistic by design.
- **Gated actions:** voting Save/Clear and wallet ops render a disabled
  "Authorize first" state when no key, re-enabling on authorize.
- **Settings dialog** loses the `api_key` field → pure prefs (theme / density /
  explorer).

### D. Wallet as a section

- `wallet/index.html` markup → a `#wallet` `<section>` in `index.html`;
  `wallet/wallet.js` → `js/wallet.js` on the new lifecycle, using shared
  components + `js/api-client.js` (extended with wallet endpoints) +
  `js/format.js`.
- **Layered secrets:** shell Authorize handles `api_key`; the wallet section
  handles server-side **unlock (password)**. States: no key → authorize prompt;
  key but locked → unlock UI; unlocked → panels.
- **Preserve safety:** poll-suspend-during-mnemonic, don't-clobber-input (now via
  `isBusy()`), the mnemonic write-down gate. Send-confirm → `<dialog>`.
- **Fix two latent issues** found in audit: optimistic send lets the same draft
  be resubmitted (reset/disable form on submit, `wallet.js:770-772`); UI logout
  doesn't lock server-side (`wallet.js:154-158` — offer/trigger wallet lock).
- Theme/density now apply to the wallet automatically (it is in the shell).

### E. Native Swagger + a11y ride-along

- Scala `swagger.html`: untouched.
- `swagger-native.html`: theme-aware (load `tokens.css`, honor the app theme),
  dedupe the duplicated banner `<style>` into a shared file, use the shared
  `.banner`, add a "set your api_key on the dashboard to pre-authorize" hint.
  Swagger-UI core CSS stays (CDN, SRI-pinned).
- a11y pass while in-file: `aria-sort` on sortable headers (`table.js:34`),
  `role=progressbar`+`aria-valuenow` on gauges, `aria-live` on status/banners,
  labels on inputs.

## Build sequence (dependency order)

1. Token cleanup + shared component layer (`tokens.css`, `components.css`).
2. Section lifecycle (`app.js`, `router.js`).
3. Authorize subsystem (`js/auth.js`, `api-client.js`, settings split, shell
   chip, Overview prompt, gated states).
4. Migrate dashboard sections onto shared components (overview/peers/mempool/
   voting; voting table → `.dtable`, voting status → `.banner`).
5. Fold wallet into the `#wallet` section.
6. Native swagger theming + dedupe.
7. a11y pass.

## Testing / verification

- Vanilla / no-build: extend the existing `?selftest` console-assert blocks for
  pure helpers (`format.js`, `fee-stats.js`).
- Per-section **manual test plan**: authorize flow incl. legacy-key migration;
  gated-action disabled states; wallet unlock/send/mnemonic with poll live;
  theme switch across *all* sections incl. wallet + native swagger; voting-table
  mobile reflow; settings-no-longer-holds-key.
- Rust gate (`cargo fmt --all -- --check`, `cargo clippy --workspace
  --all-targets --all-features -- -D warnings`, `cargo test --workspace`) only
  if the `/wallet/ui` → `#wallet` redirect touches a Rust static route.

## Risks / open calls (for codex)

1. Voting `<table>` → flex `.dtable` (one table system vs lost table
   semantics) — fallback noted in §B.
2. Folding the wallet means its ~970 lines load with the dashboard always
   (trivial when locally served; no lazy-loading without a build step).
3. Native-swagger theming scope (chrome-only vs deeper Swagger-UI theming).
4. Stacking on unmerged `feat/votes-history` — rebase coupling if that branch
   changes during review.
