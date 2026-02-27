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

/// HTML page for the Node Panel admin dashboard.
pub const PANEL_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Ergo Node Panel</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
      background: #f5f5f5;
      color: #333;
      min-height: 100vh;
    }
    header {
      background: #1a1a2e;
      color: #fff;
      padding: 1rem 2rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    header h1 { font-size: 1.4rem; font-weight: 600; }
    .badge {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 0.8em;
      font-weight: 600;
      text-transform: uppercase;
    }
    .badge-mainnet { background: #e3f2fd; color: #1565c0; }
    .badge-testnet { background: #fce4ec; color: #c62828; }
    .badge-synced { background: #e8f5e9; color: #2e7d32; }
    .badge-syncing { background: #fff3e0; color: #e65100; }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
      gap: 1.5rem;
      padding: 1.5rem;
      max-width: 1400px;
      margin: 0 auto;
    }
    .card {
      background: #fff;
      border-radius: 8px;
      padding: 1.5rem;
      box-shadow: 0 2px 8px rgba(0,0,0,0.1);
    }
    .card h2 {
      font-size: 1.1rem;
      font-weight: 600;
      margin-bottom: 1rem;
      color: #1a1a2e;
      border-bottom: 2px solid #e0e0e0;
      padding-bottom: 0.5rem;
    }
    .info-row {
      display: flex;
      justify-content: space-between;
      padding: 0.35rem 0;
      border-bottom: 1px solid #f0f0f0;
    }
    .info-row:last-child { border-bottom: none; }
    .info-label { color: #888; font-size: 0.9em; }
    .info-value { font-weight: 500; font-size: 0.9em; }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.88em;
    }
    th {
      text-align: left;
      padding: 0.5rem 0.4rem;
      border-bottom: 2px solid #e0e0e0;
      color: #666;
      font-weight: 600;
      font-size: 0.85em;
      text-transform: uppercase;
    }
    td {
      padding: 0.45rem 0.4rem;
      border-bottom: 1px solid #f0f0f0;
    }
    tr:nth-child(even) { background: #fafafa; }
    .progress-container {
      background: #e0e0e0;
      border-radius: 10px;
      height: 20px;
      overflow: hidden;
      margin: 0.75rem 0;
    }
    .progress-bar {
      height: 100%;
      border-radius: 10px;
      background: linear-gradient(90deg, #4caf50, #81c784);
      transition: width 0.5s ease;
      min-width: 0;
    }
    .progress-bar-blocks {
      background: linear-gradient(90deg, #1565c0, #42a5f5);
    }
    .hash {
      font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace;
      font-size: 0.85em;
      color: #666;
    }
    .sync-section { text-align: center; padding: 1rem 0; }
    .sync-pct { font-size: 2rem; font-weight: 700; color: #1a1a2e; }
    .sync-label { margin-top: 0.5rem; font-size: 0.95em; }
    .last-update { color: #aaa; font-size: 0.8em; margin-top: 0.75rem; }
    .empty-msg { color: #aaa; font-style: italic; padding: 0.75rem 0; }
    .error-msg { color: #c62828; font-style: italic; padding: 0.75rem 0; }
    .nav-links { display: flex; gap: 1rem; align-items: center; }
    .nav-links a {
      color: rgba(255,255,255,0.8);
      text-decoration: none;
      font-size: 0.9em;
    }
    .nav-links a:hover { color: #fff; }
    @media (max-width: 860px) {
      .grid { grid-template-columns: 1fr; padding: 1rem; }
      header { flex-direction: column; gap: 0.5rem; text-align: center; }
    }
  </style>
</head>
<body>
  <header>
    <div style="display:flex;align-items:center;gap:1rem;">
      <h1>Ergo Node Panel</h1>
      <span id="networkBadge" class="badge"></span>
    </div>
    <div class="nav-links">
      <a href="/swagger">API Docs</a>
      <a href="/info">Node Info</a>
    </div>
  </header>

  <div class="grid">
    <div class="card">
      <h2>Node Info</h2>
      <div id="nodeInfoContent">
        <div class="empty-msg">Loading...</div>
      </div>
    </div>

    <div class="card">
      <h2>Sync Status</h2>
      <div id="syncContent">
        <div class="empty-msg">Loading...</div>
      </div>
    </div>

    <div class="card">
      <h2>Connected Peers</h2>
      <div id="peersContent">
        <div class="empty-msg">Loading...</div>
      </div>
    </div>

    <div class="card">
      <h2>Mempool</h2>
      <div id="mempoolContent">
        <div class="empty-msg">Loading...</div>
      </div>
    </div>
  </div>

  <script>
    function esc(s) {
      var d = document.createElement('div');
      d.textContent = s;
      return d.innerHTML;
    }

    function fmt(n) {
      if (n == null) return '\u2014';
      return Number(n).toLocaleString('en-US');
    }

    function truncHash(h) {
      if (!h) return '\u2014';
      if (h.length <= 20) return h;
      return h.substring(0, 16) + '...';
    }

    function infoRow(label, value) {
      return '<div class="info-row">' +
        '<span class="info-label">' + esc(label) + '</span>' +
        '<span class="info-value">' + esc(String(value)) + '</span>' +
        '</div>';
    }

    function updateNodeInfo(info) {
      var net = (info.network || 'unknown').toLowerCase();
      var badge = document.getElementById('networkBadge');
      badge.textContent = net;
      badge.className = 'badge badge-' + (net === 'testnet' ? 'testnet' : 'mainnet');

      var html = infoRow('Name', info.name || '\u2014');
      html += infoRow('Version', info.appVersion || '\u2014');
      html += infoRow('Network', net);
      html += infoRow('State Type', info.stateType || '\u2014');
      html += infoRow('Headers Height', fmt(info.headersHeight));
      html += infoRow('Full Block Height', fmt(info.fullHeight));
      html += infoRow('Max Peer Height', fmt(info.maxPeerHeight));
      html += infoRow('Difficulty', fmt(info.difficulty));
      html += infoRow('Mining', info.isMining ? 'Yes' : 'No');
      html += infoRow('Peers', fmt(info.peersCount));
      html += infoRow('Unconfirmed Txs', fmt(info.unconfirmedCount));
      document.getElementById('nodeInfoContent').innerHTML = html;
    }

    function makeProgressRow(label, current, target, barClass) {
      var pct = 0;
      if (target > 0) { pct = Math.min(100, (current / target) * 100); }
      var html = '<div style="margin-bottom:1rem;">';
      html += '<div style="display:flex;justify-content:space-between;font-size:0.88em;margin-bottom:0.3rem;">';
      html += '<span style="font-weight:600;color:#1a1a2e;">' + esc(label) + '</span>';
      html += '<span style="color:#666;">' + fmt(current) + ' / ' + fmt(target) + ' (' + pct.toFixed(1) + '%)</span>';
      html += '</div>';
      html += '<div class="progress-container">';
      html += '<div class="progress-bar' + (barClass ? ' ' + barClass : '') + '" style="width:' + pct.toFixed(1) + '%"></div>';
      html += '</div></div>';
      return html;
    }

    function updateSync(info) {
      var headers = info.headersHeight || 0;
      var full = info.fullHeight || 0;
      var max = info.maxPeerHeight || 0;

      var headersDone = max > 0 && headers >= max - 1;
      var blocksDone = headers > 0 && full >= headers - 1;
      var synced = headersDone && blocksDone;

      var el = document.getElementById('syncContent');
      var html = '';

      // Overall status badge
      var statusBadge;
      if (synced) {
        statusBadge = '<span class="badge badge-synced">Synced</span>';
      } else if (!headersDone) {
        statusBadge = '<span class="badge badge-syncing">Syncing Headers...</span>';
      } else {
        statusBadge = '<span class="badge badge-syncing">Downloading Blocks...</span>';
      }
      html += '<div style="text-align:center;margin-bottom:1rem;">' + statusBadge + '</div>';

      // Headers progress: current vs max peer height
      html += makeProgressRow('Headers', headers, max, '');

      // Full blocks progress: current vs headers height
      html += makeProgressRow('Full Blocks', full, headers, 'progress-bar-blocks');

      html += '<div class="last-update">Last updated: ' + new Date().toLocaleTimeString() + '</div>';

      el.innerHTML = html;
    }

    function updatePeers(peers) {
      var el = document.getElementById('peersContent');
      if (!peers || peers.length === 0) {
        el.innerHTML = '<div class="empty-msg">No peers connected</div>';
        return;
      }

      el.innerHTML = '';

      var countDiv = document.createElement('div');
      countDiv.style.cssText = 'margin-bottom:0.75rem;font-size:0.9em;color:#666;';
      countDiv.textContent = peers.length + ' peer' + (peers.length !== 1 ? 's' : '') + ' connected';
      el.appendChild(countDiv);

      var table = document.createElement('table');
      var thead = document.createElement('thead');
      var headRow = document.createElement('tr');
      ['Address', 'Name', 'Direction'].forEach(function(h) {
        var th = document.createElement('th');
        th.textContent = h;
        headRow.appendChild(th);
      });
      thead.appendChild(headRow);
      table.appendChild(thead);

      var tbody = document.createElement('tbody');
      for (var i = 0; i < peers.length; i++) {
        var p = peers[i];
        var tr = document.createElement('tr');

        var tdAddr = document.createElement('td');
        tdAddr.className = 'hash';
        tdAddr.textContent = p.address || '\u2014';
        tr.appendChild(tdAddr);

        var tdName = document.createElement('td');
        tdName.textContent = p.name || '\u2014';
        tr.appendChild(tdName);

        var tdDir = document.createElement('td');
        tdDir.textContent = p.connectionType || '\u2014';
        tr.appendChild(tdDir);

        tbody.appendChild(tr);
      }
      table.appendChild(tbody);
      el.appendChild(table);
    }

    function updateMempool(txs) {
      var el = document.getElementById('mempoolContent');
      if (!txs || txs.length === 0) {
        el.innerHTML = '<div class="empty-msg">Mempool is empty</div>';
        return;
      }

      el.innerHTML = '';

      var countDiv = document.createElement('div');
      countDiv.style.cssText = 'margin-bottom:0.75rem;font-size:0.9em;color:#666;';
      countDiv.textContent = txs.length + ' transaction' + (txs.length !== 1 ? 's' : '') + ' shown';
      el.appendChild(countDiv);

      var table = document.createElement('table');
      var thead = document.createElement('thead');
      var headRow = document.createElement('tr');
      ['Transaction ID', 'Inputs', 'Outputs'].forEach(function(h) {
        var th = document.createElement('th');
        th.textContent = h;
        headRow.appendChild(th);
      });
      thead.appendChild(headRow);
      table.appendChild(thead);

      var tbody = document.createElement('tbody');
      for (var i = 0; i < txs.length; i++) {
        var tx = txs[i];
        var tr = document.createElement('tr');

        var tdId = document.createElement('td');
        tdId.className = 'hash';
        tdId.textContent = truncHash(tx.id);
        tr.appendChild(tdId);

        var tdIn = document.createElement('td');
        tdIn.textContent = tx.inputs ? String(tx.inputs.length) : '\u2014';
        tr.appendChild(tdIn);

        var tdOut = document.createElement('td');
        tdOut.textContent = tx.outputs ? String(tx.outputs.length) : '\u2014';
        tr.appendChild(tdOut);

        tbody.appendChild(tr);
      }
      table.appendChild(tbody);
      el.appendChild(table);
    }

    function fetchAll() {
      fetch('/info')
        .then(function(r) { return r.json(); })
        .then(function(info) {
          updateNodeInfo(info);
          updateSync(info);
        })
        .catch(function() {
          document.getElementById('nodeInfoContent').innerHTML =
            '<div class="error-msg">Error loading data</div>';
          document.getElementById('syncContent').innerHTML =
            '<div class="error-msg">Error loading data</div>';
        });

      fetch('/peers/connected')
        .then(function(r) { return r.json(); })
        .then(function(peers) { updatePeers(peers); })
        .catch(function() {
          document.getElementById('peersContent').innerHTML =
            '<div class="error-msg">Error loading data</div>';
        });

      fetch('/transactions/unconfirmed?limit=10&offset=0')
        .then(function(r) { return r.json(); })
        .then(function(txs) { updateMempool(txs); })
        .catch(function() {
          document.getElementById('mempoolContent').innerHTML =
            '<div class="error-msg">Error loading data</div>';
        });
    }

    fetchAll();
    setInterval(fetchAll, 5000);
  </script>
</body>
</html>"##;

/// Embedded OpenAPI YAML specification.
pub const OPENAPI_YAML: &str = include_str!("../assets/openapi.yaml");
