# Node Panel Overhaul Design

**Date:** 2026-03-03
**Status:** Approved
**Approach:** Preact + HTM SPA via CDN (Approach B)

## Overview

Complete overhaul of the `/panel` web UI from a basic 4-card vanilla JS page to a
full SPA with sidebar navigation, 6 pages, 4 switchable themes, a peer world map,
and sync speed charting. Delivered as a single embedded `PANEL_HTML` const in
`web_ui.rs` with zero build tooling.

## Tech Stack

| Library | Version | Size (gzip) | Purpose |
|---------|---------|-------------|---------|
| Preact | 10.x | ~4KB | Component model + reactivity |
| HTM | 3.x | ~1KB | Tagged template JSX alternative |
| Chart.js | 4.x | ~70KB | Sync speed time-series chart |
| Leaflet | 1.9.x | ~40KB | Peer world map |

All loaded from unpkg CDN. No build step, no npm.

## Layout

```
+--------------------------------------------------+
|  [Logo]  Ergo Node Panel     [theme toggle] [net] |
+----------+---------------------------------------+
|          |                                       |
| Sidebar  |  Main Content Area                    |
| 220px    |  (active page component)              |
|          |                                       |
| Dashboard|                                       |
| Network  |                                       |
| Blockchain                                       |
| Mempool  |                                       |
| Wallet   |                                       |
| System   |                                       |
|          |                                       |
| ──────── |                                       |
| External |                                       |
|  Swagger |                                       |
|  Explorer|                                       |
+----------+---------------------------------------+
```

- **Header:** Fixed top. Logo + title left, theme cycle button + network badge right.
- **Sidebar:** Fixed left 220px. Collapsible drawer on mobile (<768px).
- **Router:** Hash-based (`#/dashboard`, `#/network`, etc.).

## Pages

### Dashboard (`#/dashboard` — default)

**Row 1 — 4 stat cards:** Headers Height, Full Block Height, Connected Peers,
Unconfirmed Txs. Each shows value + secondary comparison + synced/behind indicator.

**Row 2 — 2 panels:**
- Sync Status: dual progress bars (headers + blocks), status badge, sync speed
  Chart.js line chart (last 10 min from successive `/info` polls).
- Node Info: key-value grid (Name, Version, Network, State Type, Difficulty,
  Mining, Launch Time, Genesis Block ID with copy button).

**Data:** `/info` polled every 5s.

### Network (`#/network`)

**Top:** Leaflet world map. Circle markers at peer lat/lng from GeoIP. Color by
chain status (Younger=green, Equal=blue, Older=orange, Unknown=gray). Hover
tooltip: address + agent + height.

**Bottom:** Sortable peers table. Columns: Address, Agent Name, Direction, Version,
State Type, Height, Chain Status, Country. Click headers to sort.

**Data:** `/peers/connected` polled every 10s.

### Blockchain (`#/blockchain`)

Table of last 20 headers: Height, Header ID (truncated + copy), Timestamp
(relative), Tx Count, Difficulty.

**Data:** `/blocks/lastHeaders/20` polled every 15s.

### Mempool (`#/mempool`)

Summary bar (total count). Transaction table: ID (truncated + copy), Inputs,
Outputs, Token count. Paginated 10 per page.

**Data:** `/transactions/unconfirmed?limit=10&offset=N` polled every 5s.

### Wallet (`#/wallet`)

Placeholder: info card with "Wallet functionality available when compiled with
`--features wallet`" message and description of future capabilities.

### System (`#/system`)

Info cards from `/info`: Uptime (from launchTime), State Type, Is Mining, Headers
Score, Full Blocks Score, Current Time. "More metrics coming soon" note for future
DB size / memory endpoints.

**Data:** `/info` polled every 5s.

## Themes

Four themes via CSS custom properties on `<html data-theme="...">`. Persisted to
`localStorage`. Cycled via header button (keyboard shortcut `T`).

### Light
- BG: `#f5f7fa`, Cards: `#ffffff`, Text: `#1a1a2e`
- Sidebar: `#ffffff`, Active: `#f0f2f5`
- Accents: `#2563eb` (blue), `#10b981` (green), `#f59e0b` (amber)

### Dark
- BG: `#0f1117`, Cards: `#1a1d27`, Text: `#e2e8f0`
- Sidebar: `#141620`, Active: `#1e2235`
- Accents: `#3b82f6`, `#34d399`, `#fbbf24`
- Borders: `rgba(255,255,255,0.08)`

### Terminal
- BG: `#0a0a0a`, Cards: `#111111`, Text: `#00ff41` (phosphor green)
- Sidebar: `#0a0a0a`, Active: `#1a1a1a`
- All fonts: monospace (`'SF Mono', 'Fira Code', 'Consolas'`)
- Accents: `#00ff41`, `#ff6600`, `#ff0040`
- Glow: `text-shadow: 0 0 4px` on key values
- Borders: `rgba(0,255,65,0.15)`

### Glassmorphism
- BG: `linear-gradient(135deg, #0f0c29, #302b63, #24243e)`
- Cards: `rgba(255,255,255,0.08)`, `backdrop-filter: blur(12px)`,
  `border: 1px solid rgba(255,255,255,0.12)`
- Text: `#f0f0f0`
- Sidebar: `rgba(255,255,255,0.05)` with blur
- Accents: `#a78bfa` (purple), `#34d399`, `#fbbf24`

## Component Architecture

```
App
├── ThemeProvider          (context: theme + toggle)
├── Router                 (hash-based, renders active page)
├── Shell
│   ├── Header             (logo, theme toggle, network badge)
│   ├── Sidebar            (nav links, external links, mobile drawer)
│   └── MainContent
│       ├── DashboardPage
│       ├── NetworkPage
│       ├── BlockchainPage
│       ├── MempoolPage
│       ├── WalletPage
│       └── SystemPage
└── Shared
    ├── StatCard           (icon, label, value, sub-value)
    ├── DataTable          (sortable columns)
    ├── ProgressBar        (label, current, max, color)
    ├── CopyHash           (truncated hash + clipboard)
    ├── Badge              (colored status pill)
    └── InfoRow            (label: value pair)
```

## Data Flow

```javascript
// Custom hook — each page fetches independently
const { data, loading, error } = useApi(url, intervalMs);
```

| Page | Endpoint | Interval |
|------|----------|----------|
| Dashboard | `/info` | 5s |
| Network | `/peers/connected` | 10s |
| Blockchain | `/blocks/lastHeaders/20` | 15s |
| Mempool | `/transactions/unconfirmed?limit=10&offset=N` | 5s |
| System | `/info` | 5s |

Sync chart: local array of `{time, headersHeight, fullHeight}` from `/info` polls,
last 120 points (10 min). Resets on page nav away.

Peer map: Leaflet init on mount, markers updated on each data refresh.

No global store. Shared state limited to theme (context) and route (hashchange).

## Error Handling

- **Loading (first fetch):** Skeleton placeholders (pulsing gray bars).
- **Error:** Red-tinted card, "Failed to load — retrying...", auto-retry on interval.
- **Stale data:** Shows last good data + "Connection lost" warning badge.
- **No peers:** Zero state, not error state. Empty map + "No peers connected" message.
- **Pre-sync (height 0):** "Waiting for peers..." label instead of "0 / 0".
- **No GeoIP:** Peers in table but not on map. Info message if zero geo data.
- **CDN failure:** Blank page. `<noscript>` fallback: "Use API directly at /info".

## Mobile Responsiveness

- <768px: sidebar collapses to slide-out drawer via hamburger
- Tables: horizontal scroll
- Stat cards: 2-across tablet, 1-across phone
- Peer map: 200px height vs 400px desktop
- Theme toggle + network badge stay in header

## API Requirements

**No new endpoints needed.** All pages work with existing:
- `GET /info`
- `GET /peers/connected`
- `GET /blocks/lastHeaders/{count}`
- `GET /transactions/unconfirmed?limit=N&offset=N`

Future (not blocking): `GET /node/stats` for DB size/memory on System page.

## Delivery

Single `PANEL_HTML` const in `crates/ergo-node/src/web_ui.rs`. Replaces the
existing const. Served at `GET /panel` via the existing `panel_handler` in
`api.rs`. No changes to routing or Rust API code needed.
