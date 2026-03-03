//! Web UI constants for Swagger and Node Panel.
//!
//! HTML pages are embedded as compile-time constants to avoid
//! runtime file dependencies.

/// HTML page that loads Swagger UI from CDN.
pub const SWAGGER_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Ergo Node API - Swagger UI</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
  <style>
    body { margin: 0; background: #fafafa; }
    .swagger-ui .topbar { display: none; }
  </style>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-standalone-preset.js"></script>
  <script>
    SwaggerUIBundle({
      url: '/api-docs/openapi.yaml',
      dom_id: '#swagger-ui',
      deepLinking: true,
      presets: [SwaggerUIBundle.presets.apis, SwaggerUIStandalonePreset],
      plugins: [SwaggerUIBundle.plugins.DownloadUrl],
      layout: "StandaloneLayout"
    });
  </script>
</body>
</html>"#;

/// HTML page for the Node Panel admin dashboard (Preact + HTM SPA).
pub const PANEL_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Ergo Node Panel</title>

  <!-- Import map for bare specifiers used by Preact internals -->
  <script type="importmap">
  {
    "imports": {
      "preact": "https://unpkg.com/preact@10.25.4/dist/preact.module.js",
      "preact/hooks": "https://unpkg.com/preact@10.25.4/hooks/dist/hooks.module.js",
      "htm": "https://unpkg.com/htm@3.1.1/dist/htm.module.js"
    }
  }
  </script>

  <!-- Leaflet CSS (pinned version) -->
  <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">

  <!-- Chart.js (UMD, pinned version) -->
  <script src="https://unpkg.com/chart.js@4.4.7/dist/chart.umd.js"></script>

  <!-- Leaflet JS (pinned version) -->
  <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>

  <style>
    /* ================================================================
       THEME DEFINITIONS
       ================================================================ */

    [data-theme="light"] {
      --bg: #f5f7fa;
      --bg-card: #ffffff;
      --text: #1a1a2e;
      --text-secondary: #6b7280;
      --sidebar-bg: #ffffff;
      --sidebar-active: #f0f2f5;
      --border: #e5e7eb;
      --accent: #2563eb;
      --accent-green: #10b981;
      --accent-amber: #f59e0b;
      --accent-red: #ef4444;
      --font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
      --font-mono: 'SF Mono', 'Fira Code', 'Consolas', monospace;
      --card-shadow: 0 2px 8px rgba(0,0,0,0.08);
      --card-border: 1px solid #e5e7eb;
      --card-backdrop: none;
    }

    [data-theme="dark"] {
      --bg: #0f1117;
      --bg-card: #1a1d27;
      --text: #e2e8f0;
      --text-secondary: #94a3b8;
      --sidebar-bg: #141620;
      --sidebar-active: #1e2235;
      --border: rgba(255,255,255,0.08);
      --accent: #3b82f6;
      --accent-green: #34d399;
      --accent-amber: #fbbf24;
      --accent-red: #f87171;
      --font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
      --font-mono: 'SF Mono', 'Fira Code', 'Consolas', monospace;
      --card-shadow: 0 2px 8px rgba(0,0,0,0.3);
      --card-border: 1px solid rgba(255,255,255,0.08);
      --card-backdrop: none;
    }

    [data-theme="terminal"] {
      --bg: #0a0a0a;
      --bg-card: #111111;
      --text: #00ff41;
      --text-secondary: #00cc33;
      --sidebar-bg: #0a0a0a;
      --sidebar-active: #1a1a1a;
      --border: rgba(0,255,65,0.15);
      --accent: #00ff41;
      --accent-green: #00ff41;
      --accent-amber: #ff6600;
      --accent-red: #ff0040;
      --font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace;
      --font-mono: 'SF Mono', 'Fira Code', 'Consolas', monospace;
      --card-shadow: 0 0 8px rgba(0,255,65,0.1);
      --card-border: 1px solid rgba(0,255,65,0.15);
      --card-backdrop: none;
      --glow: 0 0 4px rgba(0,255,65,0.4);
    }

    [data-theme="glass"] {
      --bg: linear-gradient(135deg, #0f0c29, #302b63, #24243e);
      --bg-card: rgba(255,255,255,0.08);
      --text: #f0f0f0;
      --text-secondary: #b0b0b0;
      --sidebar-bg: rgba(255,255,255,0.05);
      --sidebar-active: rgba(255,255,255,0.1);
      --border: rgba(255,255,255,0.12);
      --accent: #a78bfa;
      --accent-green: #34d399;
      --accent-amber: #fbbf24;
      --accent-red: #f87171;
      --font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
      --font-mono: 'SF Mono', 'Fira Code', 'Consolas', monospace;
      --card-shadow: 0 8px 32px rgba(0,0,0,0.3);
      --card-border: 1px solid rgba(255,255,255,0.12);
      --card-backdrop: blur(12px);
    }

    /* ================================================================
       BASE LAYOUT CSS
       ================================================================ */

    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    body {
      background-color: var(--bg);
      color: var(--text);
      font-family: var(--font-family);
      min-height: 100vh;
    }

    [data-theme="glass"] body {
      background: var(--bg);
      background-color: transparent;
    }

    [data-theme="terminal"] .glow-value {
      text-shadow: var(--glow);
    }

    /* --- Header --- */
    .header {
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      height: 56px;
      z-index: 100;
      background: var(--sidebar-bg);
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0 1.5rem;
    }

    [data-theme="glass"] .header {
      background: rgba(255,255,255,0.05);
      backdrop-filter: blur(12px);
    }

    .header-left {
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }

    .header-logo {
      width: 32px;
      height: 32px;
      background: var(--accent);
      border-radius: 8px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 700;
      font-size: 1.2rem;
      color: #fff;
    }

    [data-theme="terminal"] .header-logo {
      background: transparent;
      border: 1px solid var(--accent);
      color: var(--accent);
    }

    .header-title {
      font-size: 1.1rem;
      font-weight: 600;
    }

    .header-right {
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }

    .theme-btn {
      background: none;
      border: 1px solid var(--border);
      color: var(--text-secondary);
      cursor: pointer;
      border-radius: 6px;
      padding: 0.35rem 0.65rem;
      font-size: 0.85rem;
      font-family: var(--font-mono);
      transition: background 0.15s, color 0.15s;
    }

    .theme-btn:hover {
      background: var(--sidebar-active);
      color: var(--text);
    }

    .hamburger {
      display: none;
      background: none;
      border: none;
      color: var(--text);
      cursor: pointer;
      font-size: 1.4rem;
      padding: 0.25rem;
      line-height: 1;
    }

    /* --- Sidebar --- */
    .sidebar {
      position: fixed;
      left: 0;
      top: 56px;
      bottom: 0;
      width: 220px;
      background: var(--sidebar-bg);
      border-right: 1px solid var(--border);
      overflow-y: auto;
      z-index: 90;
      transition: transform 0.3s;
    }

    [data-theme="glass"] .sidebar {
      background: rgba(255,255,255,0.05);
      backdrop-filter: blur(12px);
    }

    .sidebar-section-title {
      text-transform: uppercase;
      font-size: 0.7rem;
      letter-spacing: 0.05em;
      color: var(--text-secondary);
      padding: 1rem 1.2rem 0.4rem;
      font-weight: 600;
    }

    .sidebar-nav-item {
      padding: 0.7rem 1.2rem;
      display: flex;
      align-items: center;
      gap: 0.75rem;
      color: var(--text-secondary);
      cursor: pointer;
      border-radius: 6px;
      margin: 2px 8px;
      text-decoration: none;
      font-size: 0.9rem;
      transition: background 0.15s, color 0.15s;
    }

    .sidebar-nav-item.active {
      background: var(--sidebar-active);
      color: var(--accent);
    }

    .sidebar-nav-item:hover {
      background: var(--sidebar-active);
    }

    .sidebar-nav-icon {
      width: 1.2em;
      text-align: center;
      font-size: 1rem;
    }

    .sidebar-ext-link {
      padding: 0.7rem 1.2rem;
      display: flex;
      align-items: center;
      gap: 0.75rem;
      color: var(--text-secondary);
      cursor: pointer;
      border-radius: 6px;
      margin: 2px 8px;
      text-decoration: none;
      font-size: 0.9rem;
      transition: background 0.15s, color 0.15s;
    }

    .sidebar-ext-link:hover {
      background: var(--sidebar-active);
    }

    /* --- Sidebar overlay for mobile --- */
    .sidebar-overlay {
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: rgba(0,0,0,0.5);
      z-index: 80;
      display: none;
    }

    .sidebar-overlay.active {
      display: block;
    }

    /* --- Main content --- */
    .main-content {
      margin-left: 220px;
      margin-top: 56px;
      padding: 1.5rem;
      min-height: calc(100vh - 56px);
    }

    /* --- Card --- */
    .card {
      background: var(--bg-card);
      border-radius: 10px;
      padding: 1.5rem;
      box-shadow: var(--card-shadow);
      border: var(--card-border);
      backdrop-filter: var(--card-backdrop);
    }

    .card h2 {
      font-size: 1rem;
      font-weight: 600;
      color: var(--text);
      margin-bottom: 1rem;
      padding-bottom: 0.5rem;
      border-bottom: 1px solid var(--border);
    }

    /* --- Badges --- */
    .badge {
      display: inline-block;
      padding: 2px 10px;
      border-radius: 4px;
      font-size: 0.75em;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.02em;
    }

    .badge-synced { background: rgba(16,185,129,0.15); color: var(--accent-green); }
    .badge-syncing { background: rgba(245,158,11,0.15); color: var(--accent-amber); }
    .badge-mainnet { background: rgba(37,99,235,0.15); color: var(--accent); }
    .badge-testnet { background: rgba(239,68,68,0.15); color: var(--accent-red); }
    .badge-info { background: rgba(37,99,235,0.15); color: var(--accent); }
    .badge-warning { background: rgba(245,158,11,0.15); color: var(--accent-amber); }
    .badge-error { background: rgba(239,68,68,0.15); color: var(--accent-red); }

    /* --- Hash --- */
    .hash {
      font-family: var(--font-mono);
      font-size: 0.85em;
      color: var(--text-secondary);
    }

    /* --- Stat Card --- */
    .stat-card {
      position: relative;
    }

    .stat-card .stat-icon {
      font-size: 1.2rem;
      margin-bottom: 0.5rem;
      color: var(--text-secondary);
    }

    .stat-card .stat-value {
      font-size: 1.8rem;
      font-weight: 700;
      line-height: 1.2;
    }

    .stat-card .stat-value.status-good {
      color: var(--accent-green);
    }

    .stat-card .stat-value.status-warning {
      color: var(--accent-amber);
    }

    .stat-card .stat-sub {
      font-size: 0.8rem;
      color: var(--text-secondary);
      margin-left: 0.4rem;
      font-weight: 400;
    }

    .stat-card .stat-label {
      font-size: 0.82rem;
      color: var(--text-secondary);
      margin-top: 0.25rem;
    }

    /* --- Data Table --- */
    .table-wrap {
      overflow-x: auto;
    }

    .data-table {
      width: 100%;
      border-collapse: collapse;
    }

    .data-table th {
      text-align: left;
      text-transform: uppercase;
      font-size: 0.75rem;
      letter-spacing: 0.05em;
      color: var(--text-secondary);
      padding: 0.6rem 0.5rem;
      border-bottom: 2px solid var(--border);
      white-space: nowrap;
      user-select: none;
    }

    .data-table th.align-right {
      text-align: right;
    }

    .data-table th.sortable {
      cursor: pointer;
    }

    .data-table th.sortable:hover {
      color: var(--text);
    }

    .data-table td {
      padding: 0.5rem;
      border-bottom: 1px solid var(--border);
    }

    .data-table td.align-right {
      text-align: right;
    }

    .data-table tr:hover {
      background: var(--sidebar-active);
      background: rgba(0,0,0,0.03);
    }

    [data-theme="dark"] .data-table tr:hover,
    [data-theme="terminal"] .data-table tr:hover,
    [data-theme="glass"] .data-table tr:hover {
      background: rgba(255,255,255,0.03);
    }

    .data-table .empty-message {
      padding: 1.5rem;
      text-align: center;
      color: var(--text-secondary);
      font-style: italic;
    }

    /* --- Info Row --- */
    .info-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 0.4rem 0;
      border-bottom: 1px solid var(--border);
    }

    .info-row:last-child {
      border-bottom: none;
    }

    .info-row .info-label {
      color: var(--text-secondary);
      font-size: 0.88em;
    }

    .info-row .info-value {
      font-weight: 500;
      font-size: 0.88em;
    }

    .info-row .info-value.mono {
      font-family: var(--font-mono);
    }

    /* --- Progress Bar --- */
    .progress-wrap .progress-header {
      display: flex;
      justify-content: space-between;
      font-size: 0.85rem;
      margin-bottom: 0.35rem;
    }

    .progress-wrap .progress-label {
      color: var(--text-secondary);
    }

    .progress-wrap .progress-stats {
      font-weight: 500;
    }

    .progress-wrap .progress-track {
      background: var(--border);
      height: 8px;
      border-radius: 4px;
      overflow: hidden;
    }

    .progress-wrap .progress-fill {
      height: 100%;
      border-radius: 4px;
      transition: width 0.5s ease;
    }

    .progress-wrap .progress-fill.variant-green {
      background: linear-gradient(90deg, var(--accent-green), #6ee7b7);
    }

    .progress-wrap .progress-fill.variant-blue {
      background: linear-gradient(90deg, var(--accent), #93c5fd);
    }

    .progress-wrap .progress-waiting {
      font-size: 0.85rem;
      color: var(--text-secondary);
      font-style: italic;
      padding: 0.2rem 0;
    }

    /* --- Copy Hash --- */
    .copy-hash {
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 0.3rem;
    }

    .copy-hash:hover {
      color: var(--accent);
    }

    .copy-hash .copied-tip {
      font-size: 0.75rem;
      color: var(--accent-green);
      font-family: var(--font-family);
    }

    /* --- Skeleton loading --- */
    @keyframes pulse {
      0%, 100% { opacity: 0.4; }
      50% { opacity: 1.0; }
    }

    .skeleton {
      background: var(--border);
      border-radius: 4px;
      animation: pulse 1.5s ease-in-out infinite;
    }

    /* --- Grid utilities --- */
    .stat-grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 1rem;
    }

    .panel-grid {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 1.5rem;
    }

    /* ================================================================
       MOBILE BREAKPOINTS
       ================================================================ */

    @media (max-width: 768px) {
      .sidebar {
        transform: translateX(-100%);
      }

      .sidebar.sidebar-open {
        transform: translateX(0);
      }

      .hamburger {
        display: block;
      }

      .main-content {
        margin-left: 0;
      }

      .stat-grid {
        grid-template-columns: repeat(2, 1fr);
      }

      .panel-grid {
        grid-template-columns: 1fr;
      }
    }

    @media (max-width: 480px) {
      .stat-grid {
        grid-template-columns: 1fr;
      }
    }

    /* ================================================================
       MAP STYLES
       ================================================================ */

    .map-container {
      height: 400px;
      border-radius: 8px;
      overflow: hidden;
      position: relative;
    }
    .map-overlay {
      position: absolute;
      top: 0; left: 0; right: 0; bottom: 0;
      display: flex;
      align-items: center;
      justify-content: center;
      background: rgba(0,0,0,0.4);
      color: #fff;
      font-size: 0.9rem;
      z-index: 500;
      pointer-events: none;
    }
    .map-legend {
      position: absolute;
      bottom: 10px;
      right: 10px;
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 8px 12px;
      font-size: 0.75rem;
      z-index: 500;
      display: flex;
      flex-direction: column;
      gap: 4px;
    }
    .map-legend-item {
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .map-legend-dot {
      width: 10px;
      height: 10px;
      border-radius: 50%;
      display: inline-block;
    }
    @media (max-width: 768px) {
      .map-container { height: 200px; }
    }
    .pagination {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 1rem;
      margin-top: 1rem;
      font-size: 0.88rem;
    }
    .pagination button {
      background: var(--bg-card);
      color: var(--text);
      border: 1px solid var(--border);
      border-radius: 4px;
      padding: 0.4rem 0.8rem;
      cursor: pointer;
      font-size: 0.85rem;
    }
    .pagination button:hover:not(:disabled) {
      background: var(--sidebar-active);
    }
    .pagination button:disabled {
      opacity: 0.4;
      cursor: default;
    }
  </style>
</head>
<body>
  <noscript>
    <div style="padding:2rem;text-align:center;font-family:sans-serif;">
      <h2>JavaScript Required</h2>
      <p>The Ergo Node Panel requires JavaScript to function. Access the API directly at <a href="/info">/info</a>.</p>
    </div>
  </noscript>
  <div id="app"></div>

  <script type="module">
    import { h, render, createContext } from 'preact';
    import { useState, useEffect, useCallback, useRef, useMemo, useContext } from 'preact/hooks';
    import htm from 'htm';
    const html = htm.bind(h);

    // ================================================================
    // THEME CONTEXT
    // ================================================================

    const THEMES = ['light', 'dark', 'terminal', 'glass'];
    const THEME_ICONS = { light: 'sun', dark: 'moon', terminal: '>_', glass: 'gem' };

    const ThemeContext = createContext();

    function ThemeProvider({ children }) {
      const [theme, setTheme] = useState(() => {
        const saved = localStorage.getItem('ergo-panel-theme');
        return saved && THEMES.includes(saved) ? saved : 'dark';
      });

      useEffect(() => {
        document.documentElement.setAttribute('data-theme', theme);
        localStorage.setItem('ergo-panel-theme', theme);
      }, [theme]);

      const cycleTheme = useCallback(() => {
        setTheme(prev => {
          const idx = THEMES.indexOf(prev);
          return THEMES[(idx + 1) % THEMES.length];
        });
      }, []);

      return html`
        <${ThemeContext.Provider} value=${{ theme, cycleTheme }}>
          ${children}
        <//>
      `;
    }

    // ================================================================
    // ROUTE CONTEXT (single hashchange listener shared by all consumers)
    // ================================================================

    const RouteContext = createContext();

    function getRoute() {
      const hash = location.hash.replace(/^#/, '');
      return hash || '/dashboard';
    }

    function RouteProvider({ children }) {
      const [route, setRoute] = useState(getRoute);

      useEffect(() => {
        const handler = () => setRoute(getRoute());
        window.addEventListener('hashchange', handler);
        return () => window.removeEventListener('hashchange', handler);
      }, []);

      return html`<${RouteContext.Provider} value=${route}>${children}<//>`;
    }

    function useRoute() {
      return useContext(RouteContext);
    }

    // ================================================================
    // NETWORK CONTEXT
    // ================================================================

    const NetworkContext = createContext();

    function NetworkProvider({ children }) {
      const [network, setNetwork] = useState(null);
      return html`
        <${NetworkContext.Provider} value=${{ network, setNetwork }}>
          ${children}
        <//>
      `;
    }

    // ================================================================
    // SIDEBAR STATE (mobile)
    // ================================================================

    function useSidebar() {
      const [open, setOpen] = useState(false);
      const toggle = useCallback(() => setOpen(v => !v), []);
      const close = useCallback(() => setOpen(false), []);
      return { open, toggle, close };
    }

    // ================================================================
    // HELPER FUNCTIONS
    // ================================================================

    function fmt(n) {
      if (n === null || n === undefined) return '\u2014';
      return Number(n).toLocaleString('en-US');
    }

    function truncHash(h, n) {
      if (!h) return '\u2014';
      if (h.length <= n) return h;
      return h.substring(0, n) + '...';
    }

    function relativeTime(timestampMs) {
      const diff = Date.now() - timestampMs;
      if (diff < 60000) return 'just now';
      const mins = Math.floor(diff / 60000);
      if (mins < 60) return mins + 'm ago';
      const hrs = Math.floor(mins / 60);
      if (hrs < 24) return hrs + 'h ago';
      const days = Math.floor(hrs / 24);
      return days + 'd ago';
    }

    function formatUptime(launchTimeMs) {
      const diff = Date.now() - launchTimeMs;
      const totalMins = Math.floor(diff / 60000);
      const d = Math.floor(totalMins / 1440);
      const h = Math.floor((totalMins % 1440) / 60);
      const m = totalMins % 60;
      let parts = [];
      if (d > 0) parts.push(d + 'd');
      if (h > 0) parts.push(h + 'h');
      parts.push(m + 'm');
      return parts.join(' ');
    }

    // ================================================================
    // useApi HOOK
    // ================================================================

    function useApi(url, intervalMs) {
      const [data, setData] = useState(null);
      const [loading, setLoading] = useState(true);
      const [error, setError] = useState(null);

      useEffect(() => {
        const controller = new AbortController();
        let timer = null;
        let hasData = false;

        function doFetch() {
          fetch(url, { signal: controller.signal })
            .then(res => {
              if (!res.ok) throw new Error('HTTP ' + res.status);
              return res.json();
            })
            .then(json => {
              setData(json);
              setLoading(false);
              setError(null);
              hasData = true;
            })
            .catch(err => {
              if (err.name === 'AbortError') return;
              if (hasData) {
                setError(err);
              } else {
                setError(err);
                setLoading(false);
              }
            });
        }

        doFetch();
        if (intervalMs) {
          timer = setInterval(doFetch, intervalMs);
        }

        return () => {
          controller.abort();
          if (timer) clearInterval(timer);
        };
      }, [url, intervalMs]);

      return { data, loading, error };
    }

    // ================================================================
    // usePagedApi HOOK
    // ================================================================

    function usePagedApi(baseUrl, limit, intervalMs) {
      const [page, setPage] = useState(0);
      const offset = page * limit;
      const url = baseUrl + '?limit=' + limit + '&offset=' + offset;
      const { data, loading, error } = useApi(url, intervalMs);

      const nextPage = useCallback(() => setPage(p => p + 1), []);
      const prevPage = useCallback(() => setPage(p => (p > 0 ? p - 1 : 0)), []);

      return { data, loading, error, page, nextPage, prevPage, setPage };
    }

    // ================================================================
    // StatCard COMPONENT
    // ================================================================

    function StatCard({ icon, label, value, subValue, status }) {
      const statusClass = status === 'good' ? ' status-good'
        : status === 'warning' ? ' status-warning' : '';

      return html`
        <div class="stat-card card">
          ${icon && html`<div class="stat-icon">${icon}</div>`}
          <div style="display:flex;align-items:baseline">
            <span class="stat-value glow-value${statusClass}">${value}</span>
            ${subValue && html`<span class="stat-sub">${subValue}</span>`}
          </div>
          <div class="stat-label">${label}</div>
        </div>
      `;
    }

    // ================================================================
    // DataTable COMPONENT
    // ================================================================

    function DataTable({ columns, data, emptyMessage }) {
      const [sort, setSort] = useState({ key: null, dir: 'asc' });

      const handleSort = useCallback((key) => {
        setSort(prev => ({
          key,
          dir: prev.key === key && prev.dir === 'asc' ? 'desc' : 'asc',
        }));
      }, []);

      const sorted = useMemo(() => {
        if (!data || !sort.key) return data || [];
        const arr = [...data];
        arr.sort((a, b) => {
          const va = a[sort.key];
          const vb = b[sort.key];
          if (va == null && vb == null) return 0;
          if (va == null) return 1;
          if (vb == null) return -1;
          if (typeof va === 'number' && typeof vb === 'number') {
            return sort.dir === 'asc' ? va - vb : vb - va;
          }
          const sa = String(va);
          const sb = String(vb);
          const cmp = sa.localeCompare(sb);
          return sort.dir === 'asc' ? cmp : -cmp;
        });
        return arr;
      }, [data, sort.key, sort.dir]);

      if (!data || data.length === 0) {
        return html`<div class="data-table empty-message">${emptyMessage || 'No data'}</div>`;
      }

      return html`
        <div class="table-wrap">
          <table class="data-table">
            <thead>
              <tr>
                ${columns.map(col => {
                  const alignCls = col.align === 'right' ? ' align-right' : '';
                  const sortCls = col.sortable ? ' sortable' : '';
                  const indicator = sort.key === col.key
                    ? (sort.dir === 'asc' ? ' \u25B2' : ' \u25BC') : '';
                  return html`
                    <th
                      class="${alignCls}${sortCls}"
                      onClick=${col.sortable ? () => handleSort(col.key) : undefined}
                      key=${col.key}
                    >
                      ${col.label}${indicator}
                    </th>
                  `;
                })}
              </tr>
            </thead>
            <tbody>
              ${sorted.map((row, ri) => html`
                <tr key=${ri}>
                  ${columns.map(col => {
                    const alignCls = col.align === 'right' ? ' align-right' : '';
                    const cellVal = col.render
                      ? col.render(row[col.key], row)
                      : row[col.key];
                    return html`<td class="${alignCls}" key=${col.key}>${cellVal}</td>`;
                  })}
                </tr>
              `)}
            </tbody>
          </table>
        </div>
      `;
    }

    // ================================================================
    // ProgressBar COMPONENT
    // ================================================================

    function ProgressBar({ label, current, max, variant }) {
      const v = variant || 'green';

      if (max === 0) {
        return html`
          <div class="progress-wrap">
            <div class="progress-header">
              <span class="progress-label">${label}</span>
            </div>
            <div class="progress-waiting">Waiting for peers...</div>
          </div>
        `;
      }

      const pct = Math.min(100, Math.round((current / max) * 100));

      return html`
        <div class="progress-wrap">
          <div class="progress-header">
            <span class="progress-label">${label}</span>
            <span class="progress-stats">${fmt(current)} / ${fmt(max)} (${pct}%)</span>
          </div>
          <div class="progress-track">
            <div class="progress-fill variant-${v}" style="width:${pct}%"></div>
          </div>
        </div>
      `;
    }

    // ================================================================
    // CopyHash COMPONENT
    // ================================================================

    function CopyHash({ hash, chars }) {
      const n = chars || 16;
      const [copied, setCopied] = useState(false);

      const handleClick = useCallback(() => {
        if (!hash) return;
        navigator.clipboard.writeText(hash).then(() => {
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        });
      }, [hash]);

      const display = hash
        ? (hash.length <= n ? hash : hash.substring(0, n) + '...')
        : '\u2014';

      return html`
        <span class="copy-hash hash" title=${hash || ''} onClick=${handleClick}>
          ${display}
          ${copied && html`<span class="copied-tip">Copied!</span>`}
        </span>
      `;
    }

    // ================================================================
    // Badge COMPONENT
    // ================================================================

    function Badge({ text, variant }) {
      const cls = variant ? 'badge badge-' + variant : 'badge';
      return html`<span class=${cls}>${text}</span>`;
    }

    // ================================================================
    // InfoRow COMPONENT
    // ================================================================

    function InfoRow({ label, value, mono }) {
      const valueCls = 'info-value' + (mono ? ' mono' : '');
      return html`
        <div class="info-row">
          <span class="info-label">${label}</span>
          <span class=${valueCls}>${value}</span>
        </div>
      `;
    }

    // ================================================================
    // Skeleton COMPONENT
    // ================================================================

    function Skeleton({ lines }) {
      const count = lines || 4;
      const widths = ['100%', '90%', '95%', '80%'];
      const bars = [];
      for (let i = 0; i < count; i++) {
        const w = widths[i % widths.length];
        bars.push(html`
          <div
            key=${i}
            class="skeleton"
            style="height:14px;margin-bottom:10px;border-radius:4px;width:${w}"
          ></div>
        `);
      }
      return html`<div>${bars}</div>`;
    }

    // ================================================================
    // KEYBOARD SHORTCUTS
    // ================================================================

    function KeyboardShortcuts() {
      const { cycleTheme } = useContext(ThemeContext);

      useEffect(() => {
        const handler = (e) => {
          if (e.key === 't' || e.key === 'T') {
            const tag = e.target.tagName;
            if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return;
            cycleTheme();
          }
        };
        window.addEventListener('keydown', handler);
        return () => window.removeEventListener('keydown', handler);
      }, [cycleTheme]);

      return null;
    }

    // ================================================================
    // STALE WARNING COMPONENT
    // ================================================================

    function StaleWarning({ error }) {
      if (!error) return null;
      return html`
        <div style="display:flex;align-items:center;gap:0.5rem;padding:0.5rem 0.75rem;background:rgba(245,158,11,0.1);border-radius:6px;font-size:0.8rem;color:var(--accent-amber);margin-bottom:1rem;">
          <span>\u26A0</span>
          <span>Connection lost \u2014 showing cached data, retrying...</span>
        </div>
      `;
    }

    // ================================================================
    // HEADER COMPONENT
    // ================================================================

    function Header({ sidebarToggle }) {
      const { theme, cycleTheme } = useContext(ThemeContext);
      const { network } = useContext(NetworkContext);

      const themeLabel = THEME_ICONS[theme] || theme;

      const networkBadge = network
        ? html`<span class="badge ${network === 'testnet' ? 'badge-testnet' : 'badge-mainnet'}">${network}</span>`
        : null;

      return html`
        <div class="header">
          <div class="header-left">
            <button class="hamburger" onClick=${sidebarToggle} aria-label="Toggle menu">
              <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="2">
                <line x1="3" y1="5" x2="17" y2="5"/>
                <line x1="3" y1="10" x2="17" y2="10"/>
                <line x1="3" y1="15" x2="17" y2="15"/>
              </svg>
            </button>
            <div class="header-logo">
              <svg width="18" height="18" viewBox="0 0 18 18" fill="none" xmlns="http://www.w3.org/2000/svg">
                <text x="9" y="14" text-anchor="middle" fill="currentColor" font-size="14" font-weight="700" font-family="serif">&#931;</text>
              </svg>
            </div>
            <span class="header-title">Ergo Node Panel</span>
          </div>
          <div class="header-right">
            ${networkBadge}
            <button class="theme-btn" onClick=${cycleTheme} title="Cycle theme">${themeLabel}</button>
          </div>
        </div>
      `;
    }

    // ================================================================
    // SIDEBAR COMPONENT
    // ================================================================

    const NAV_PAGES = [
      { path: '/dashboard', label: 'Dashboard', icon: '\u25EB' },
      { path: '/network',   label: 'Network',   icon: '\u2B21' },
      { path: '/blockchain',label: 'Blockchain', icon: '\u26D3' },
      { path: '/mempool',   label: 'Mempool',    icon: '\u21B9' },
      { path: '/wallet',    label: 'Wallet',     icon: '\u229E' },
      { path: '/system',    label: 'System',     icon: '\u2699' },
    ];

    const NAV_EXTERNAL = [
      { href: '/swagger', label: 'Swagger', icon: '\u2630' },
      { href: 'https://explorer.ergoplatform.com', label: 'Explorer', icon: '\u2197', external: true },
      { href: 'https://ergoplatform.org', label: 'Website', icon: '\u2316', external: true },
    ];

    function Sidebar({ open, close }) {
      const route = useRoute();

      return html`
        <nav class="sidebar ${open ? 'sidebar-open' : ''}">
          <div class="sidebar-section-title">Pages</div>
          ${NAV_PAGES.map(item => html`
            <a
              class="sidebar-nav-item ${route === item.path ? 'active' : ''}"
              href="#${item.path}"
              onClick=${close}
              key=${item.path}
              aria-current=${route === item.path ? 'page' : undefined}
            >
              <span class="sidebar-nav-icon">${item.icon}</span>
              <span>${item.label}</span>
            </a>
          `)}

          <div class="sidebar-section-title" style="margin-top:0.5rem">External</div>
          ${NAV_EXTERNAL.map(item => html`
            <a
              class="sidebar-ext-link"
              href=${item.href}
              target=${item.external ? '_blank' : '_self'}
              rel=${item.external ? 'noopener noreferrer' : undefined}
              key=${item.href}
            >
              <span class="sidebar-nav-icon">${item.icon}</span>
              <span>${item.label}</span>
            </a>
          `)}
        </nav>
      `;
    }

    // ================================================================
    // SIDEBAR OVERLAY (mobile)
    // ================================================================

    function SidebarOverlay({ open, close }) {
      return html`<div class="sidebar-overlay ${open ? 'active' : ''}" onClick=${close}></div>`;
    }

    // ================================================================
    // PLACEHOLDER PAGES
    // ================================================================

    function DashboardPage() {
      const { data: info, loading, error } = useApi('/info', 5000);
      const { setNetwork } = useContext(NetworkContext);
      const { theme } = useContext(ThemeContext);
      const chartRef = useRef(null);
      const canvasRef = useRef(null);
      const historyRef = useRef([]);

      // Update network context when info loads
      useEffect(() => {
        if (info && info.network) {
          setNetwork(info.network);
        }
      }, [info && info.network]);

      // Push sync data to history on each info update
      useEffect(() => {
        if (!info) return;
        const history = historyRef.current;
        history.push({
          time: Date.now(),
          headers: info.headersHeight || 0,
          blocks: info.fullHeight || 0,
        });
        // Keep last 120 entries
        if (history.length > 120) {
          history.splice(0, history.length - 120);
        }
      }, [info && info.headersHeight, info && info.fullHeight]);

      // Chart.js effect: create/recreate on data or theme change
      useEffect(() => {
        if (!canvasRef.current) return;
        const history = historyRef.current;

        // Destroy previous chart
        if (chartRef.current) {
          chartRef.current.destroy();
          chartRef.current = null;
        }

        if (history.length < 2) return;

        // Compute rates
        const labels = [];
        const headersRates = [];
        const blocksRates = [];

        for (let i = 1; i < history.length; i++) {
          const prev = history[i - 1];
          const curr = history[i];
          const dtSec = (curr.time - prev.time) / 1000;
          if (dtSec <= 0) continue;
          const hRate = Math.max(0, (curr.headers - prev.headers) / dtSec);
          const bRate = Math.max(0, (curr.blocks - prev.blocks) / dtSec);
          const d = new Date(curr.time);
          const hh = String(d.getHours()).padStart(2, '0');
          const mm = String(d.getMinutes()).padStart(2, '0');
          const ss = String(d.getSeconds()).padStart(2, '0');
          labels.push(hh + ':' + mm + ':' + ss);
          headersRates.push(hRate);
          blocksRates.push(bRate);
        }

        // Read colors from CSS variables
        const cs = getComputedStyle(document.documentElement);
        const greenColor = cs.getPropertyValue('--accent-green').trim() || '#10b981';
        const blueColor = cs.getPropertyValue('--accent').trim() || '#2563eb';
        const textSecondary = cs.getPropertyValue('--text-secondary').trim() || '#6b7280';
        const borderColor = cs.getPropertyValue('--border').trim() || '#e5e7eb';

        const ctx = canvasRef.current.getContext('2d');
        chartRef.current = new Chart(ctx, {
          type: 'line',
          data: {
            labels: labels,
            datasets: [
              {
                label: 'Headers/s',
                data: headersRates,
                borderColor: greenColor,
                backgroundColor: greenColor + '22',
                borderWidth: 2,
                pointRadius: 0,
                tension: 0.3,
                fill: true,
              },
              {
                label: 'Blocks/s',
                data: blocksRates,
                borderColor: blueColor,
                backgroundColor: blueColor + '22',
                borderWidth: 2,
                pointRadius: 0,
                tension: 0.3,
                fill: true,
              },
            ],
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: { duration: 300 },
            interaction: { intersect: false, mode: 'index' },
            plugins: {
              legend: {
                labels: { color: textSecondary, boxWidth: 12, padding: 8, font: { size: 11 } },
              },
            },
            scales: {
              x: {
                ticks: { color: textSecondary, maxTicksLimit: 8, font: { size: 10 } },
                grid: { color: borderColor },
              },
              y: {
                beginAtZero: true,
                ticks: { color: textSecondary, font: { size: 10 } },
                grid: { color: borderColor },
              },
            },
          },
        });

        return () => {
          if (chartRef.current) {
            chartRef.current.destroy();
            chartRef.current = null;
          }
        };
      }, [info && info.headersHeight, info && info.fullHeight, theme]);

      // Loading state
      if (loading) {
        return html`<div class="card"><h2>Dashboard</h2><${Skeleton} lines=${6} /></div>`;
      }

      // Error state with no data
      if (error && !info) {
        return html`
          <div class="card">
            <h2>Dashboard</h2>
            <p style="color:var(--accent-red)">Failed to load node info \u2014 retrying...</p>
          </div>
        `;
      }

      // Stale data warning (info exists but connection lost)
      const staleWarning = (info && error) ? html`<${StaleWarning} error=${error} />` : null;

      // Compute statuses
      const headersCaughtUp = info.headersHeight >= (info.maxPeerHeight || 0) - 1;
      const blocksCaughtUp = info.fullHeight >= (info.headersHeight || 0) - 1;

      const headersStatus = headersCaughtUp ? 'good'
        : (info.maxPeerHeight > 0 ? 'warning' : 'normal');
      const blocksStatus = blocksCaughtUp ? 'good'
        : (info.headersHeight > 0 ? 'warning' : 'normal');

      // Sync badge
      let syncBadgeText, syncBadgeVariant;
      if (headersCaughtUp && blocksCaughtUp) {
        syncBadgeText = 'Synced';
        syncBadgeVariant = 'synced';
      } else if (!headersCaughtUp) {
        syncBadgeText = 'Syncing Headers...';
        syncBadgeVariant = 'syncing';
      } else {
        syncBadgeText = 'Downloading Blocks...';
        syncBadgeVariant = 'syncing';
      }

      const now = new Date();
      const lastUpdated = String(now.getHours()).padStart(2, '0') + ':'
        + String(now.getMinutes()).padStart(2, '0') + ':'
        + String(now.getSeconds()).padStart(2, '0');

      const hasChartData = historyRef.current.length >= 2;

      return html`
        <div>
          ${staleWarning}
          <div class="stat-grid" style="margin-bottom:1.5rem">
            <${StatCard}
              icon="\u2B06"
              label="Headers Height"
              value=${fmt(info.headersHeight)}
              subValue=${' / ' + fmt(info.maxPeerHeight)}
              status=${headersStatus}
            />
            <${StatCard}
              icon="\u25FC"
              label="Full Block Height"
              value=${fmt(info.fullHeight)}
              subValue=${' / ' + fmt(info.headersHeight)}
              status=${blocksStatus}
            />
            <${StatCard}
              icon="\u2B21"
              label="Connected Peers"
              value=${fmt(info.peersCount)}
            />
            <${StatCard}
              icon="\u21B9"
              label="Unconfirmed Txs"
              value=${fmt(info.unconfirmedCount)}
            />
          </div>

          <div class="panel-grid">
            <div class="card">
              <h2>Sync Status</h2>
              <div style="margin-bottom:1rem">
                <${Badge} text=${syncBadgeText} variant=${syncBadgeVariant} />
              </div>
              <div style="margin-bottom:0.75rem">
                <${ProgressBar}
                  label="Headers"
                  current=${info.headersHeight || 0}
                  max=${info.maxPeerHeight || 0}
                  variant="green"
                />
              </div>
              <div style="margin-bottom:1rem">
                <${ProgressBar}
                  label="Full Blocks"
                  current=${info.fullHeight || 0}
                  max=${info.headersHeight || 0}
                  variant="blue"
                />
              </div>
              <div style="position:relative;height:180px;margin-bottom:0.75rem">
                ${!hasChartData && html`
                  <div style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);color:var(--text-secondary);font-style:italic;font-size:0.9rem">
                    Collecting sync data...
                  </div>
                `}
                <canvas ref=${canvasRef} style="width:100%;height:100%"></canvas>
              </div>
              <div style="font-size:0.8rem;color:var(--text-secondary);text-align:right">
                Last updated: ${lastUpdated}
              </div>
            </div>

            <div class="card">
              <h2>Node Info</h2>
              <${InfoRow} label="Name" value=${info.name} />
              <${InfoRow} label="Version" value=${info.appVersion} />
              <${InfoRow} label="Network" value=${info.network} />
              <${InfoRow} label="State Type" value=${info.stateType} />
              <${InfoRow} label="Difficulty" value=${fmt(info.difficulty)} />
              <${InfoRow} label="Mining" value=${info.isMining ? 'Yes' : 'No'} />
              <${InfoRow} label="Launch Time" value=${new Date(info.launchTime).toLocaleString()} />
              <${InfoRow} label="Genesis Block ID" value=${html`<${CopyHash} hash=${info.genesisBlockId} />`} />
            </div>
          </div>
        </div>
      `;
    }

    function NetworkPage() {
      const { data: peers, loading, error } = useApi('/peers/connected', 10000);
      const { theme } = useContext(ThemeContext);
      const mapRef = useRef(null);
      const tileRef = useRef(null);
      const markersRef = useRef(null);
      const mapElRef = useRef(null);

      // Initialize Leaflet map once the map div is in the DOM
      // We depend on `loading` so this re-runs when loading finishes and the div appears
      useEffect(() => {
        if (loading) return;
        const mapEl = document.getElementById('peer-map');
        if (!mapEl || mapRef.current) return;
        const map = L.map(mapEl, {
          center: [20, 0],
          zoom: 2,
          zoomControl: true,
          attributionControl: false
        });
        mapRef.current = map;
        mapElRef.current = mapEl;

        const isDark = theme === 'dark' || theme === 'terminal' || theme === 'glass';
        const tileUrl = isDark
          ? 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png'
          : 'https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png';
        tileRef.current = L.tileLayer(tileUrl).addTo(map);

        markersRef.current = L.layerGroup().addTo(map);

        return () => {
          map.remove();
          mapRef.current = null;
          tileRef.current = null;
          markersRef.current = null;
        };
      }, [loading]);

      // Update tile layer on theme change
      useEffect(() => {
        if (!mapRef.current || !tileRef.current) return;
        const isDark = theme === 'dark' || theme === 'terminal' || theme === 'glass';
        const tileUrl = isDark
          ? 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png'
          : 'https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png';
        mapRef.current.removeLayer(tileRef.current);
        tileRef.current = L.tileLayer(tileUrl).addTo(mapRef.current);
      }, [theme]);

      // Update markers when peers data changes
      useEffect(() => {
        if (!markersRef.current || !peers) return;
        markersRef.current.clearLayers();
        peers.forEach(peer => {
          if (peer.geo && peer.geo.latitude != null && peer.geo.longitude != null) {
            L.circleMarker([peer.geo.latitude, peer.geo.longitude], {
              radius: 6,
              fillColor: colorForStatus(peer.chainStatus),
              fillOpacity: 0.8,
              color: colorForStatus(peer.chainStatus),
              weight: 1,
              opacity: 0.9
            }).bindTooltip(
              (peer.address || 'Unknown') + '\n' +
              (peer.name || 'Unknown') + '\n' +
              'Height: ' + (peer.height || '?')
            ).addTo(markersRef.current);
          }
        });
      }, [peers]);

      function colorForStatus(status) {
        switch (status) {
          case 'Younger': return '#10b981';
          case 'Equal':   return '#3b82f6';
          case 'Older':   return '#f59e0b';
          default:        return '#6b7280';
        }
      }

      if (loading) return html`<div class="card"><h2>Network</h2><${Skeleton} lines=${6} /></div>`;

      if (error && !peers) {
        return html`<div class="card"><h2>Network</h2><p style="color:var(--text-secondary)">Failed to load peer data \u2014 retrying...</p></div>`;
      }

      const networkStaleWarning = (peers && error) ? html`<${StaleWarning} error=${error} />` : null;

      const peerList = peers || [];
      const hasGeo = peerList.some(p => p.geo && p.geo.latitude != null && p.geo.longitude != null);

      // Pre-process peers for table: flatten geo.countryCode
      const tableData = peerList.map(p => ({
        ...p,
        country: (p.geo && p.geo.countryCode) || '\u2014'
      }));

      const columns = [
        {
          label: 'Address', key: 'address', sortable: true,
          render: (v) => html`<span class="hash">${v || '\u2014'}</span>`
        },
        { label: 'Agent', key: 'name', sortable: true },
        { label: 'Node Name', key: 'nodeName', sortable: true,
          render: (v) => v || '\u2014'
        },
        {
          label: 'Direction', key: 'connectionType',
          render: (v) => v === 'Incoming' ? '\u2193 In' : '\u2191 Out'
        },
        { label: 'Version', key: 'version', sortable: true },
        { label: 'State Type', key: 'stateType' },
        {
          label: 'Height', key: 'height', sortable: true, align: 'right',
          render: (v) => fmt(v)
        },
        {
          label: 'Chain Status', key: 'chainStatus', sortable: true,
          render: (v) => {
            const variant = v === 'Younger' ? 'synced'
              : v === 'Equal' ? 'info'
              : v === 'Older' ? 'warning' : 'info';
            return html`<${Badge} text=${v || 'Unknown'} variant=${variant} />`;
          }
        },
        { label: 'Country', key: 'country', sortable: true }
      ];

      return html`
        <div>
          ${networkStaleWarning}
          <div class="card">
            <h2>Peer Map</h2>
            <div style="position:relative">
              <div id="peer-map" class="map-container"></div>
              ${!hasGeo && html`<div class="map-overlay">GeoIP database not configured</div>`}
              <div class="map-legend">
                <div class="map-legend-item">
                  <span class="map-legend-dot" style="background:#10b981"></span>
                  <span>Younger</span>
                </div>
                <div class="map-legend-item">
                  <span class="map-legend-dot" style="background:#3b82f6"></span>
                  <span>Equal</span>
                </div>
                <div class="map-legend-item">
                  <span class="map-legend-dot" style="background:#f59e0b"></span>
                  <span>Older</span>
                </div>
                <div class="map-legend-item">
                  <span class="map-legend-dot" style="background:#6b7280"></span>
                  <span>Unknown</span>
                </div>
              </div>
            </div>
          </div>

          <div class="card" style="margin-top:1.5rem">
            <h2>Connected Peers <span style="font-weight:normal;font-size:0.9rem;color:var(--text-secondary)">\u2014 ${peerList.length} peers connected</span></h2>
            <${DataTable}
              columns=${columns}
              data=${tableData}
              emptyMessage="No peers connected"
            />
          </div>
        </div>
      `;
    }

    function BlockchainPage() {
      const { data: headers, loading, error } = useApi('/blocks/lastHeaders/20', 15000);

      if (loading) return html`<${Skeleton} />`;
      if (error && !headers) return html`<div class="card"><h2>Error</h2><p style="color:var(--text-secondary)">${error}</p></div>`;

      const blockchainStaleWarning = (headers && error) ? html`<${StaleWarning} error=${error} />` : null;

      const columns = [
        { key: 'height', label: 'Height', sortable: true, align: 'right', render: (v) => fmt(v) },
        { key: 'id', label: 'Header ID', render: (v) => html`<${CopyHash} hash=${v} chars=${16} />` },
        { key: 'timestamp', label: 'Timestamp', sortable: true, render: (v) => html`<span title="${new Date(v).toLocaleString()}">${relativeTime(v)}</span>` },
        { key: 'nBits', label: 'Difficulty', sortable: true, render: (v) => '0x' + v.toString(16) },
        { key: 'votes', label: 'Votes', render: (v) => v },
      ];

      return html`
        <div>
          ${blockchainStaleWarning}
          <div class="card">
            <h2>Recent Blocks</h2>
            <p style="color:var(--text-secondary)">Last 20 block headers</p>
          </div>
          <${DataTable} columns=${columns} data=${headers || []} emptyMessage="No blocks synced yet" />
        </div>
      `;
    }

    function MempoolPage() {
      const { data: txs, loading, error, page, nextPage, prevPage } = usePagedApi(
        '/transactions/unconfirmed', 10, 5000
      );

      if (loading) return html`<${Skeleton} />`;
      if (error && !txs) return html`<div class="card"><h2>Error</h2><p style="color:var(--text-secondary)">${error}</p></div>`;

      const mempoolStaleWarning = (txs && error) ? html`<${StaleWarning} error=${error} />` : null;

      const columns = [
        { key: 'id', label: 'TX ID', render: (v) => html`<${CopyHash} hash=${v} chars=${16} />` },
        { key: 'inputs', label: 'Inputs', render: (v) => v ? v.length : 0 },
        { key: 'outputs', label: 'Outputs', render: (v) => v ? v.length : 0 },
        { key: 'outputs', label: 'Tokens', render: (v, row) => {
          const tokenIds = new Set();
          if (row.outputs) row.outputs.forEach(o => { if (o.assets) o.assets.forEach(a => tokenIds.add(a.tokenId)); });
          return tokenIds.size;
        }},
      ];

      return html`
        <div>
          ${mempoolStaleWarning}
          <div class="card">
            <h2>Mempool</h2>
            <p style="color:var(--text-secondary)">Page ${page + 1}</p>
          </div>
          <${DataTable} columns=${columns} data=${txs || []} emptyMessage="Mempool is empty" />
          <div class="pagination">
            <button disabled=${page === 0} onClick=${prevPage}>Prev</button>
            <span>Page ${page + 1}</span>
            <button disabled=${txs == null || txs.length < 10} onClick=${nextPage}>Next</button>
          </div>
        </div>
      `;
    }

    function WalletPage() {
      return html`
        <div class="card" style="text-align:center;padding:3rem 2rem;">
          <div style="font-size:3rem;margin-bottom:1rem;">⊡</div>
          <h2 style="border:none;padding:0;margin-bottom:0.75rem;">Wallet</h2>
          <p style="color:var(--text-secondary);max-width:400px;margin:0 auto 1rem;">
            Wallet functionality is available when the node is compiled with the
            <code style="background:var(--sidebar-active);padding:0.15rem 0.4rem;border-radius:3px;font-family:var(--font-mono);font-size:0.85em;">--features wallet</code> flag.
          </p>
          <p style="color:var(--text-secondary);font-size:0.85rem;max-width:400px;margin:0 auto;">
            Planned capabilities: HD key management, balance tracking, transaction signing, and payment requests.
          </p>
        </div>
      `;
    }

    function SystemPage() {
      const { data: info, loading, error } = useApi('/info', 5000);

      if (loading) return html`<${Skeleton} />`;
      if (error && !info) return html`<div class="card"><h2>Error</h2><p style="color:var(--accent-red)">${error}</p></div>`;

      const systemStaleWarning = (info && error) ? html`<${StaleWarning} error=${error} />` : null;

      return html`
        <div>
        ${systemStaleWarning}
        <div class="stat-grid" style="grid-template-columns:repeat(3,1fr)">
          <${StatCard} icon="⏱" label="Uptime" value=${formatUptime(info.launchTime)} />
          <${StatCard} icon="◫" label="State Type" value=${info.stateType.charAt(0).toUpperCase() + info.stateType.slice(1)} />
          <${StatCard} icon="⛏" label="Mining" value=${info.isMining ? 'Active' : 'Inactive'} status=${info.isMining ? 'good' : 'normal'} />
        </div>

        <div class="card">
          <h2>Chain Scores</h2>
          <${InfoRow} label="Headers Score" value=${info.headersScore} mono=${true} />
          <${InfoRow} label="Full Blocks Score" value=${info.fullBlocksScore} mono=${true} />
        </div>

        <div class="card">
          <h2>Details</h2>
          <${InfoRow} label="Sync State" value=${info.syncState} />
          <${InfoRow} label="Current Time" value=${new Date(info.currentTime).toLocaleString()} />
          <${InfoRow} label="EIP-27 (Re-emission)" value=${info.eip27Supported ? 'Supported' : 'Not supported'} />
          <${InfoRow} label="EIP-37 (Difficulty)" value=${info.eip37Supported ? 'Supported' : 'Not supported'} />
          <${InfoRow} label="Explorer Mode" value=${info.isExplorer ? 'Enabled' : 'Disabled'} />
        </div>

        <div class="card" style="border-left:3px solid var(--accent);opacity:0.8;">
          <h2 style="font-size:0.9rem;">Extended Metrics</h2>
          <p style="color:var(--text-secondary);font-size:0.85rem;">
            Database size, memory usage, and system resource monitoring will be available in a future release.
          </p>
        </div>
        </div>
      `;
    }

    // ================================================================
    // ROUTER COMPONENT
    // ================================================================

    const ROUTES = {
      '/dashboard': DashboardPage,
      '/network': NetworkPage,
      '/blockchain': BlockchainPage,
      '/mempool': MempoolPage,
      '/wallet': WalletPage,
      '/system': SystemPage,
    };

    function Router() {
      const route = useRoute();
      const Page = ROUTES[route] || DashboardPage;
      return html`<${Page} />`;
    }

    // ================================================================
    // APP COMPONENT
    // ================================================================

    function App() {
      const sidebar = useSidebar();

      return html`
        <${ThemeProvider}>
          <${KeyboardShortcuts} />
          <${RouteProvider}>
            <${NetworkProvider}>
              <${Header} sidebarToggle=${sidebar.toggle} />
              <${Sidebar} open=${sidebar.open} close=${sidebar.close} />
              <${SidebarOverlay} open=${sidebar.open} close=${sidebar.close} />
              <main class="main-content">
                <${Router} />
              </main>
            <//>
          <//>
        <//>
      `;
    }

    // ================================================================
    // MOUNT
    // ================================================================

    render(html`<${App} />`, document.getElementById('app'));
  </script>
</body>
</html>"##;

/// Embedded OpenAPI YAML specification.
pub const OPENAPI_YAML: &str = include_str!("../assets/openapi.yaml");
