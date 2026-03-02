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

  <!-- Leaflet CSS -->
  <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9/dist/leaflet.css">

  <!-- Chart.js (UMD) -->
  <script src="https://unpkg.com/chart.js@4"></script>

  <!-- Leaflet JS -->
  <script src="https://unpkg.com/leaflet@1.9/dist/leaflet.js"></script>

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

    /* --- Hash --- */
    .hash {
      font-family: var(--font-mono);
      font-size: 0.85em;
      color: var(--text-secondary);
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
    }

    @media (max-width: 480px) {
      .stat-grid {
        grid-template-columns: 1fr;
      }
    }
  </style>
</head>
<body>
  <noscript>
    <div style="padding:2rem;text-align:center;font-family:sans-serif;">
      <h2>JavaScript Required</h2>
      <p>The Ergo Node Panel requires JavaScript to function. Please enable JavaScript and reload.</p>
    </div>
  </noscript>
  <div id="app"></div>

  <script type="module">
    import { h, render, createContext } from 'https://unpkg.com/preact@10/dist/preact.module.js';
    import { useState, useEffect, useCallback, useRef, useMemo, useContext } from 'https://unpkg.com/preact@10/hooks/dist/hooks.module.js';
    import htm from 'https://unpkg.com/htm@3/dist/htm.module.js';
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
    // ROUTER
    // ================================================================

    function useRoute() {
      const getRoute = () => {
        const hash = location.hash.replace(/^#/, '');
        return hash || '/dashboard';
      };

      const [route, setRoute] = useState(getRoute);

      useEffect(() => {
        const handler = () => setRoute(getRoute());
        window.addEventListener('hashchange', handler);
        return () => window.removeEventListener('hashchange', handler);
      }, []);

      return route;
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

      const navigate = useCallback((path) => {
        location.hash = path;
        close();
      }, [close]);

      return html`
        <nav class="sidebar ${open ? 'sidebar-open' : ''}">
          <div class="sidebar-section-title">Pages</div>
          ${NAV_PAGES.map(item => html`
            <div
              class="sidebar-nav-item ${route === item.path ? 'active' : ''}"
              onClick=${() => navigate(item.path)}
              key=${item.path}
            >
              <span class="sidebar-nav-icon">${item.icon}</span>
              <span>${item.label}</span>
            </div>
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
      return html`<div class="card"><h2>Dashboard</h2><p style="color:var(--text-secondary)">Coming soon...</p></div>`;
    }

    function NetworkPage() {
      return html`<div class="card"><h2>Network</h2><p style="color:var(--text-secondary)">Coming soon...</p></div>`;
    }

    function BlockchainPage() {
      return html`<div class="card"><h2>Blockchain</h2><p style="color:var(--text-secondary)">Coming soon...</p></div>`;
    }

    function MempoolPage() {
      return html`<div class="card"><h2>Mempool</h2><p style="color:var(--text-secondary)">Coming soon...</p></div>`;
    }

    function WalletPage() {
      return html`<div class="card"><h2>Wallet</h2><p style="color:var(--text-secondary)">Coming soon...</p></div>`;
    }

    function SystemPage() {
      return html`<div class="card"><h2>System</h2><p style="color:var(--text-secondary)">Coming soon...</p></div>`;
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
          <${NetworkProvider}>
            <${Header} sidebarToggle=${sidebar.toggle} />
            <${Sidebar} open=${sidebar.open} close=${sidebar.close} />
            <${SidebarOverlay} open=${sidebar.open} close=${sidebar.close} />
            <main class="main-content">
              <${Router} />
            </main>
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
