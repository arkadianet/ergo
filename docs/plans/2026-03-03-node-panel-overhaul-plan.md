# Node Panel Overhaul Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace the basic 4-card vanilla JS node panel with a full Preact+HTM SPA featuring 6 sidebar pages, 4 switchable themes, a peer world map, and sync speed charting.

**Architecture:** Single `PANEL_HTML` const in `crates/ergo-node/src/web_ui.rs` containing a complete Preact+HTM SPA. CDN-loaded dependencies (Preact, HTM, Chart.js, Leaflet). Hash-based routing, CSS custom property theming, `useApi()` polling hook. No build tooling, no npm.

**Tech Stack:** Preact 10 + HTM 3 (CDN), Chart.js 4, Leaflet 1.9, CSS custom properties, vanilla hash routing.

**Design doc:** `docs/plans/2026-03-03-node-panel-overhaul-design.md`

---

## Important Context

**File to modify:** `crates/ergo-node/src/web_ui.rs`
- Contains `pub const PANEL_HTML: &str = r##"..."##;` (lines 37-457)
- Also contains `SWAGGER_HTML` (lines 7-34) and `OPENAPI_YAML` (line 460) — do NOT touch these
- The `PANEL_HTML` const is the ONLY thing that changes

**Existing API endpoints used (no changes needed):**
- `GET /info` → `NodeInfoResponse` with fields: name, appVersion, network, headersHeight, fullHeight, maxPeerHeight, bestHeaderId, stateType, peersCount, unconfirmedCount, difficulty, headersScore, fullBlocksScore, launchTime, genesisBlockId, isMining, currentTime, syncState
- `GET /peers/connected` → Array of peer objects with: address, name, connectionType, version, stateType, height, chainStatus, geo {countryCode, city, latitude, longitude}
- `GET /blocks/lastHeaders/{n}` → Array of header objects with: id, height, timestamp, nBits, votes, transactionsRoot, parentId, powSolutions
- `GET /transactions/unconfirmed?limit=N&offset=N` → Array of tx objects with: id, inputs[], outputs[]

**Routing (no changes needed):** `api.rs:1678` serves `crate::web_ui::PANEL_HTML` at `GET /panel`.

**Verification after every task:**
```bash
cargo fmt --check
cargo clippy --workspace -- -D warnings
cargo build --release
# Then open http://localhost:9052/panel in browser to visually verify
```

---

## Task 1: HTML Skeleton + CDN Imports + Theme CSS Foundation

**Files:**
- Modify: `crates/ergo-node/src/web_ui.rs` (replace `PANEL_HTML` const, lines 37-457)

**What to build:**
Replace the entire `PANEL_HTML` const with a new HTML page that has:

1. **`<head>` section** with CDN imports:
   - Preact 10: `https://unpkg.com/preact@10/dist/preact.module.js` (ESM)
   - Preact hooks: `https://unpkg.com/preact@10/hooks/dist/hooks.module.js`
   - HTM: `https://unpkg.com/htm@3/dist/htm.module.js`
   - Chart.js 4: `https://unpkg.com/chart.js@4` (UMD, loaded via `<script>`)
   - Leaflet 1.9 CSS: `https://unpkg.com/leaflet@1.9/dist/leaflet.css`
   - Leaflet 1.9 JS: `https://unpkg.com/leaflet@1.9/dist/leaflet.js`
   - Viewport meta tag for mobile

2. **CSS `<style>` block** with:
   - 4 complete theme definitions as CSS custom properties on `[data-theme="light"]`, `[data-theme="dark"]`, `[data-theme="terminal"]`, `[data-theme="glass"]`
   - Variables for: `--bg`, `--bg-card`, `--text`, `--text-secondary`, `--sidebar-bg`, `--sidebar-active`, `--border`, `--accent`, `--accent-green`, `--accent-amber`, `--accent-red`, `--font-family`, `--font-mono`, `--card-shadow`, `--card-border`, `--card-backdrop`
   - Terminal theme overrides `--font-family` to monospace and adds `--glow`
   - Glass theme sets `--card-backdrop: blur(12px)` and gradient `--bg`
   - Base layout styles: `*` reset, body, header (fixed top, 56px height), sidebar (fixed left, 220px, top below header), main content (margin-left 220px, margin-top 56px, padding)
   - Card base class, info-row, progress-bar, badge, hash/mono, stat-card, table
   - Mobile breakpoint at 768px: sidebar hidden by default, hamburger visible, `.sidebar-open` class slides it in
   - Skeleton loading animation (`@keyframes pulse`)
   - `<noscript>` fallback message

3. **Minimal `<script type="module">` block** that:
   - Imports Preact (h, render), hooks (useState, useEffect, useCallback, useRef, useMemo), and HTM
   - Binds HTM to Preact's h: `const html = htm.bind(h)`
   - Creates a `ThemeContext` using `preact.createContext()`
   - Implements `ThemeProvider` component that reads/writes `localStorage.getItem('ergo-panel-theme')`, defaults to `'dark'`, sets `document.documentElement.dataset.theme`
   - Implements a simple hash `Router` component: reads `location.hash`, listens to `hashchange`, renders matching page component (defaults to `#/dashboard`)
   - Implements `App` shell component with Header, Sidebar, and Router inside ThemeProvider
   - Renders `<App />` into `document.getElementById('app')`
   - Header shows "Ergo Node Panel" title, theme cycle button, placeholder network badge
   - Sidebar shows 6 nav links + 3 external links, highlights active route
   - Main content shows the routed page (for now, each page is just a placeholder `<div>Page Name</div>`)

**Key patterns for the Preact+HTM code:**

```javascript
// ESM imports at top of script module
import { h, render, createContext } from 'https://unpkg.com/preact@10/dist/preact.module.js';
import { useState, useEffect, useCallback, useRef, useMemo, useContext } from 'https://unpkg.com/preact@10/hooks/dist/hooks.module.js';
import htm from 'https://unpkg.com/htm@3/dist/htm.module.js';
const html = htm.bind(h);

// Components use html tagged templates
function MyComponent({ prop }) {
  return html`<div class="my-class">${prop}</div>`;
}
```

**Verification:**
- `cargo build --release` compiles
- `cargo clippy --workspace -- -D warnings` passes
- Browser: page loads, shows sidebar with nav links, header with theme toggle, clicking theme button cycles through Light→Dark→Terminal→Glass, mobile hamburger works
- Each nav link changes the hash and shows a placeholder page name

**Commit:** `feat(panel): scaffold Preact+HTM SPA shell with 4-theme system`

---

## Task 2: Shared Components + useApi Hook

**Files:**
- Modify: `crates/ergo-node/src/web_ui.rs` (add to the `<script>` section)

**What to build:**
Add these shared utilities and components inside the existing `<script type="module">` block, after the imports and before the page components:

1. **`useApi(url, intervalMs)` hook:**
   ```javascript
   function useApi(url, intervalMs) {
     const [data, setData] = useState(null);
     const [loading, setLoading] = useState(true);
     const [error, setError] = useState(null);
     // fetch on mount, then setInterval
     // on success: setData, setLoading(false), setError(null)
     // on error after previous success: keep old data, setError(err)
     // on error first time: setError(err), setLoading(false)
     // cleanup: clearInterval on unmount
     return { data, loading, error };
   }
   ```

2. **`usePagedApi(baseUrl, limit, intervalMs)` hook** (for mempool pagination):
   - Adds `offset` state and `nextPage`/`prevPage` callbacks
   - Returns `{ data, loading, error, page, nextPage, prevPage }`

3. **`StatCard` component:**
   - Props: `{ icon, label, value, subValue, status }`
   - Status: 'normal' | 'good' | 'warning' — applies accent color
   - Shows icon (emoji or SVG), large value, label below, optional sub-value in smaller text

4. **`DataTable` component:**
   - Props: `{ columns, data, emptyMessage }`
   - `columns`: array of `{ key, label, render?, sortable? }`
   - Click-to-sort on sortable columns (ascending/descending toggle)
   - `render` is optional custom cell renderer function
   - Horizontal scroll wrapper for mobile

5. **`ProgressBar` component:**
   - Props: `{ label, current, max, barClass }`
   - Shows label, "current / max (pct%)", animated bar
   - If max === 0, shows "Waiting for peers..." instead

6. **`CopyHash` component:**
   - Props: `{ hash, chars }`
   - Truncates to first `chars` (default 16) + "..."
   - Click copies full hash to clipboard, shows brief "Copied!" tooltip
   - Monospace font

7. **`Badge` component:**
   - Props: `{ text, variant }` where variant is 'synced' | 'syncing' | 'mainnet' | 'testnet' | 'info'
   - Colored pill using CSS classes

8. **`InfoRow` component:**
   - Props: `{ label, value, mono }`
   - Flex row with label left, value right, optional mono font for value

9. **`Skeleton` component:**
   - Props: `{ lines }` (default 4)
   - Renders N pulsing gray bars for loading state

10. **Helper functions:**
    - `fmt(n)` — locale-formatted number or em-dash for null
    - `truncHash(h, n)` — truncate hash string
    - `relativeTime(timestampMs)` — "2m ago", "1h ago", etc.
    - `formatUptime(launchTimeMs)` — "2d 5h 32m"

**Verification:**
- `cargo build --release` compiles
- Components exist but aren't used by pages yet — no visual change (pages are still placeholders)
- No JS console errors on page load

**Commit:** `feat(panel): add shared components (StatCard, DataTable, useApi, etc.)`

---

## Task 3: Dashboard Page

**Files:**
- Modify: `crates/ergo-node/src/web_ui.rs` (replace dashboard placeholder in `<script>`)

**What to build:**
Replace the `DashboardPage` placeholder with a full implementation:

1. **Data fetching:** `const { data: info, loading, error } = useApi('/info', 5000);`

2. **Network badge in header:** When info loads, update the header's network badge (pass network via context or callback prop from App). Badge shows "mainnet" or "testnet" with appropriate color.

3. **Row 1 — 4 StatCards** in a CSS grid (4 columns, 2 on tablet, 1 on phone):
   - Headers Height: value=`info.headersHeight`, subValue=`/ ${info.maxPeerHeight}`, status based on whether caught up
   - Full Block Height: value=`info.fullHeight`, subValue=`/ ${info.headersHeight}`, status based on sync
   - Connected Peers: value=`info.peersCount`, icon=network icon
   - Unconfirmed Txs: value=`info.unconfirmedCount`, icon=tx icon

4. **Row 2 — Two panels** in a 2-column grid (stacks on mobile):
   - **Sync Status card:**
     - Status badge: Synced (green) / Syncing Headers (amber) / Downloading Blocks (amber)
     - `ProgressBar` for headers (current=headersHeight, max=maxPeerHeight)
     - `ProgressBar` for blocks (current=fullHeight, max=headersHeight, barClass for blue)
     - Chart.js line chart below: maintain a `useRef` array of `{time, headers, blocks}` snapshots, push on each `/info` response, keep last 120 points. Render with Chart.js — two lines (headers rate, blocks rate), computed as delta between consecutive snapshots. Chart theme colors follow CSS variables — read from computed style.
     - "Last updated: HH:MM:SS" timestamp

   - **Node Info card:**
     - `InfoRow` entries: Name, Version, Network, State Type, Difficulty (formatted), Mining (Yes/No), Launch Time (formatted date), Genesis Block ID (CopyHash)

5. **Loading state:** Show `Skeleton` components until first data arrives.
6. **Error state:** Show error card if fetch fails entirely.

**Chart.js theme integration:**
```javascript
// Read CSS variable colors for chart theming
const style = getComputedStyle(document.documentElement);
const textColor = style.getPropertyValue('--text-secondary').trim();
const gridColor = style.getPropertyValue('--border').trim();
// Apply to chart options: scales.x.ticks.color, scales.y.grid.color, etc.
// Destroy and recreate chart on theme change (listen to theme context)
```

**Verification:**
- Browser: Dashboard shows 4 stat cards with live data from `/info`
- Sync progress bars animate
- Chart.js renders sync speed over time (initially one point, grows)
- Theme switch updates chart colors
- Loading skeletons show briefly on first load
- Mobile: stat cards stack, panels stack

**Commit:** `feat(panel): implement Dashboard page with stat cards, sync bars, and speed chart`

---

## Task 4: Network Page

**Files:**
- Modify: `crates/ergo-node/src/web_ui.rs` (replace network placeholder in `<script>`)

**What to build:**

1. **Data fetching:** `const { data: peers, loading, error } = useApi('/peers/connected', 10000);`

2. **Peer Map (top section):**
   - Leaflet map initialized in a `useEffect` on mount with `useRef` for the map instance
   - Dark tile layer that works across themes: `https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png` for dark/terminal/glass, `https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png` for light theme. Switch tile layer on theme change.
   - Default view: world zoom `[20, 0]` zoom level 2
   - On peers data update: clear existing markers layer group, add `L.circleMarker` for each peer that has `geo.latitude` and `geo.longitude`
   - Marker color by chainStatus: `'Younger'` → green (`var(--accent-green)`), `'Equal'` → blue (`var(--accent)`), `'Older'` → amber (`var(--accent-amber)`), default → gray
   - Marker radius: 6, fillOpacity: 0.8
   - Tooltip on hover: `${address}\n${name}\nHeight: ${height}`
   - If no peers have geo data: show info message overlay on map: "GeoIP database not configured — run with geoip_path setting to enable peer map"
   - Map container height: 400px desktop, 200px mobile
   - Legend in bottom-right corner showing color meanings

3. **Peers Table (bottom section):**
   - `DataTable` component with columns:
     - Address (mono font, sortable)
     - Agent Name (sortable)
     - Direction: `connectionType` — show "In" / "Out" with subtle icon
     - Version (sortable)
     - State Type
     - Height (right-aligned, formatted number, sortable)
     - Chain Status (Badge component, sortable)
     - Country (from `geo.countryCode`, sortable)
   - Default sort: Height descending
   - Count label above table: "N peers connected"

4. **Empty state:** "No peers connected" message, empty map

**Verification:**
- Browser: Network tab shows world map with colored dots at peer locations
- Hovering dots shows tooltip
- Peers table below is sortable by clicking column headers
- Theme switch changes map tile layer (light tiles for light theme, dark for others)
- Mobile: map is shorter, table scrolls horizontally

**Commit:** `feat(panel): implement Network page with Leaflet peer map and sortable table`

---

## Task 5: Blockchain Page

**Files:**
- Modify: `crates/ergo-node/src/web_ui.rs` (replace blockchain placeholder in `<script>`)

**What to build:**

1. **Data fetching:** `const { data: headers, loading, error } = useApi('/blocks/lastHeaders/20', 15000);`

2. **Page title:** "Recent Blocks" with a subtitle "Last 20 block headers"

3. **Blocks table** using `DataTable`:
   - Columns:
     - Height (formatted number, right-aligned, sortable)
     - Header ID (`CopyHash` component, 16 chars)
     - Timestamp (relative time via `relativeTime()`, tooltip shows full ISO date, sortable)
     - Difficulty (formatted from `nBits` — show raw nBits hex, sortable)
     - Votes (3-byte hex string from `votes` field)
   - Default sort: Height descending (newest first, as returned by API)

4. **Empty state:** "No blocks synced yet" message

**Note on the `/blocks/lastHeaders/{n}` response:** Each element is a `HeaderResponse` with fields: `id`, `height`, `timestamp`, `nBits`, `votes`, `transactionsRoot`, `parentId`, `adProofsRoot`, `stateRoot`, `extensionHash`, `powSolutions`, `version`. Use `height`, `id`, `timestamp`, `nBits`, `votes`.

**Verification:**
- Browser: Blockchain tab shows table of 20 headers with heights, truncated IDs, relative times
- Clicking a hash copies it
- Column sorting works
- Theme colors apply

**Commit:** `feat(panel): implement Blockchain page with recent blocks table`

---

## Task 6: Mempool Page

**Files:**
- Modify: `crates/ergo-node/src/web_ui.rs` (replace mempool placeholder in `<script>`)

**What to build:**

1. **Data fetching with pagination:**
   ```javascript
   const { data: txs, loading, error, page, nextPage, prevPage } = usePagedApi(
     '/transactions/unconfirmed', 10, 5000
   );
   ```

2. **Summary bar:** "N unconfirmed transactions" (get total from Dashboard's `/info` data if available, or just show current page count)

3. **Transaction table** using `DataTable`:
   - Columns:
     - TX ID (`CopyHash`, 16 chars)
     - Inputs (count: `tx.inputs.length`)
     - Outputs (count: `tx.outputs.length`)
     - Tokens (count unique token IDs across all outputs: count distinct `tokenId` values in `tx.outputs[].assets[]` if present, else 0)

4. **Pagination controls** below table:
   - "< Prev" / "Next >" buttons
   - "Page N" label
   - Prev disabled on page 0
   - Next disabled when returned results < limit (end of list)

5. **Empty state:** "Mempool is empty" message

**Verification:**
- Browser: Mempool tab shows transaction table, pagination works
- Copy hash works
- Empty mempool shows clean message
- Auto-refreshes every 5s

**Commit:** `feat(panel): implement Mempool page with paginated transaction table`

---

## Task 7: Wallet + System Pages

**Files:**
- Modify: `crates/ergo-node/src/web_ui.rs` (replace wallet and system placeholders)

**What to build:**

### Wallet Page
A clean placeholder card (not an error state):
- Large wallet icon (SVG or emoji)
- Title: "Wallet"
- Message: "Wallet functionality is available when the node is compiled with the `wallet` feature flag."
- Sub-message: "Planned capabilities: HD key management, balance tracking, transaction signing, and payment requests."
- Styled as an info card centered in the content area

### System Page

1. **Data fetching:** `const { data: info, loading, error } = useApi('/info', 5000);`

2. **Stat cards row** (3 across):
   - Uptime: computed from `info.launchTime` — `formatUptime(Date.now() - info.launchTime)`, updates each render
   - State Type: `info.stateType` (digest/utxo) with appropriate icon
   - Mining: `info.isMining` — "Active" (green) / "Inactive" (neutral)

3. **Scoring card:**
   - `InfoRow`: Headers Score = `info.headersScore`
   - `InfoRow`: Full Blocks Score = `info.fullBlocksScore`

4. **Details card:**
   - `InfoRow`: Sync State = `info.syncState`
   - `InfoRow`: Current Time = formatted `info.currentTime`
   - `InfoRow`: EIP-27 = `info.eip27Supported` (Yes/No)
   - `InfoRow`: EIP-37 = `info.eip37Supported` (Yes/No)
   - `InfoRow`: Explorer Mode = `info.isExplorer` (Yes/No)

5. **"Coming soon" card:**
   - Title: "Extended Metrics"
   - Message: "Database size, memory usage, and system resource monitoring will be available in a future release."
   - Styled as a subtle info card

**Verification:**
- Wallet page: shows clean placeholder card, not broken/error
- System page: shows uptime ticking, state type, mining status, scores, details
- Theme switching works on both pages

**Commit:** `feat(panel): implement Wallet placeholder and System info pages`

---

## Task 8: Polish, Mobile, Error States, and Final Verification

**Files:**
- Modify: `crates/ergo-node/src/web_ui.rs` (refinements throughout)

**What to build:**

1. **Keyboard shortcut:** Add `keydown` listener for `T` key (when not in input) to cycle themes. Already mentioned in design.

2. **Mobile hamburger menu:**
   - Verify sidebar drawer works on <768px
   - Clicking a nav link closes the drawer
   - Overlay backdrop behind drawer when open

3. **Loading skeletons:** Verify each page shows skeleton placeholders on first load, not a blank area or flash.

4. **Error states:** Verify each page shows red-tinted error card if API is unreachable, with "Failed to load — retrying..." message.

5. **Stale data indicator:** If a fetch fails after previous success, show a small "Connection lost" warning badge in the header or on the affected card, but keep showing last good data.

6. **Leaflet cleanup:** Ensure map properly destroys on component unmount (when navigating away from Network page) to prevent memory leaks. Use `useEffect` cleanup function.

7. **Chart.js cleanup:** Ensure chart properly destroys on Dashboard unmount. Clear the snapshot history array.

8. **Theme persistence verification:** Reload the page — theme should persist from localStorage.

9. **`<noscript>` fallback:** Add `<noscript><div style="padding:2rem;font-family:sans-serif;">Node panel requires JavaScript. Access the API directly at <a href="/info">/info</a></div></noscript>` in the body.

10. **Final CSS audit:**
    - Verify all 4 themes render correctly across all 6 pages
    - Terminal theme: monospace everywhere, green glow on key values
    - Glass theme: blur effect on cards, gradient background
    - No visual overflow or clipping issues
    - Tables don't break on narrow screens

**Verification (comprehensive):**
```bash
cargo fmt --check
cargo clippy --workspace -- -D warnings
cargo build --release
cargo test --workspace
```

Browser checklist:
- [ ] All 6 pages load and show data
- [ ] Theme toggle cycles through 4 themes correctly
- [ ] Theme persists across page reload
- [ ] 'T' key cycles themes
- [ ] Sidebar navigation highlights active page
- [ ] Mobile: hamburger opens drawer, nav links close it
- [ ] Dashboard: stat cards, progress bars, sync chart
- [ ] Network: map with colored markers, sortable table
- [ ] Blockchain: block table with copy-hash
- [ ] Mempool: tx table with pagination
- [ ] Wallet: clean placeholder
- [ ] System: uptime, scores, details
- [ ] Error state: stop the node, verify panel shows "Connection lost"
- [ ] Restart node: verify panel recovers and shows data again

**Commit:** `feat(panel): polish mobile layout, error states, and keyboard shortcuts`

---

## Task Summary

| Task | Description | Key Components |
|------|-------------|----------------|
| 1 | HTML skeleton + CDN + themes + shell | 4 theme CSS, header, sidebar, router |
| 2 | Shared components + useApi | StatCard, DataTable, ProgressBar, CopyHash, hooks |
| 3 | Dashboard page | Stat cards, sync bars, Chart.js speed chart |
| 4 | Network page | Leaflet peer map, sortable peers table |
| 5 | Blockchain page | Recent blocks table |
| 6 | Mempool page | Paginated tx table |
| 7 | Wallet + System pages | Placeholder + info cards |
| 8 | Polish + verification | Mobile, errors, keyboard, final QA |
