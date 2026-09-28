// Peers page: composition strip (direction / state / agents) + the shared
// sortable card-row table with a per-peer detail drawer. In/Out show each
// peer's post-handshake framed bytes (plumbed through ergo-p2p).
// Live connect/disconnect from WS `peers`; HTTP samples traffic and IP lookups.
import { api } from './api-client.js';
import { makeTable, copyBtn } from './table.js';
import { num, dur, bytes } from './format.js';
import { createChannelSub } from './ws-client.js';

let root = null;
let table = null;
let ourHeight = null;
// Traffic counters and lookup completions need sampling even without peer churn.
const HTTP_FALLBACK_MS = 5_000;
let lastFullAt = 0;
let refreshTimer = null;
let refreshing = false;
let lastPeers = [];
let trafficSamples = new Map();

function sampleTraffic(peers) {
  const next = new Map();
  const sampled = peers.map((p) => {
    const at = p.details?.sampled_at_unix_ms;
    const previous = trafficSamples.get(p.addr);
    const elapsed = previous && at != null ? (at - previous.at) / 1000 : 0;
    const sameConnection = previous && p.connected_seconds >= previous.connected_seconds &&
      p.connected_seconds >= elapsed &&
      p.details?.session_id === previous.session_id &&
      p.details?.connection_setup_ms === previous.connection_setup_ms;
    const rate = (key) => sameConnection && elapsed > 0 && elapsed <= 120 &&
      p[key] != null && previous[key] != null && p[key] >= previous[key]
      ? (p[key] - previous[key]) / elapsed : null;
    const result = { ...p, rate_in: rate('bytes_in'), rate_out: rate('bytes_out') };
    // A refresh can read the same snapshot twice. Preserve its last valid rate.
    if (sameConnection && elapsed === 0) {
      result.rate_in = previous.rate_in;
      result.rate_out = previous.rate_out;
    }
    next.set(p.addr, { ...result, at, session_id: p.details?.session_id, connection_setup_ms: p.details?.connection_setup_ms });
    return result;
  });
  trafficSamples = next;
  return sampled;
}

function stacked(primary, secondary) {
  const node = document.createElement('span');
  node.className = 'peer-stack';
  node.append(span(primary || '—'));
  if (secondary) node.append(span(secondary, 'var(--tx3)'));
  return node;
}

function modeName(mode) {
  if (!mode) return 'Not advertised';
  return mode.state_type === 0 ? 'UTXO' : mode.state_type === 1 ? 'Digest' : `Unknown (${mode.state_type})`;
}

function retention(mode) {
  if (!mode) return 'Not advertised';
  const n = mode.blocks_to_keep;
  return n === -1 ? 'All blocks' : n === -2 ? 'UTXO bootstrap' : n === 0 ? 'Headers-only' : n > 0 ? `Last ${num(n)} blocks` : `Unknown (${n})`;
}

function chainLabel(status) {
  // PeerChainStatus is the peer's chain relative to ours.
  return ({ Equal: 'Same tip', Younger: 'Behind us', Older: 'Ahead of us', Fork: 'Different branch', Nonsense: 'Invalid sync information', Unknown: 'Unknown' })[status] || 'Not observed';
}

function rateText(rate) { return rate == null ? 'Sampling…' : `${bytes(rate)}/s`; }

function lookupStatus(status) {
  return ({ pending: 'Resolving…', resolved: 'Resolved', unavailable: 'No hostname returned', timeout: 'Lookup timed out', disabled: 'Disabled', not_public: 'Local or special address', not_configured: 'No local database', downloading: 'Downloading database…', not_found: 'No database record', error: 'Database unavailable', available: 'Available' })[status] || 'Unavailable';
}

function peerLookupNote(peers) {
  const statuses = peers.flatMap((p) => [p.network?.geo_status, p.network?.asn_status]);
  if (statuses.includes('error')) return 'An IP database is unavailable. Check the node log and [api.peer_details] configuration. Failed automatic downloads retry after 24 hours.';
  if (statuses.includes('downloading')) return 'Downloading optional IP databases. Location and ASN details will appear automatically when ready; peer IPs are looked up locally.';
  if (statuses.includes('not_configured')) return 'Location and ASN details are optional. Enable auto_download in [api.peer_details] and restart, or supply local database files. Reverse DNS requires a separate opt-in.';
  return '';
}

function peerMatches(p, query) {
  const n = p.network || {};
  return [p.addr, p.agent, p.version, p.node_name, p.declared_address, p.rest_api_url,
    n.hostname, n.country, n.country_code, n.city, n.region, n.organization, n.network_cidr,
    n.asn == null ? null : `AS${n.asn}`, modeName(p.details?.mode)]
    .some((v) => String(v || '').toLowerCase().includes(query));
}

const peersWs = createChannelSub({
  id: 'peers-panel',
  channels: ['peers'],
  onEvent(frame) {
    if (frame.type !== 'event' || frame.channel !== 'peers') return;
    if (frame.event !== 'peer_connected' && frame.event !== 'peer_disconnected') return;
    scheduleRefresh(200);
  },
});

const dirColor = (d) => (d === 'outbound' ? 'var(--blue)' : 'var(--purple)');
const stateColor = (s) =>
  s === 'connected' || s === 'active' ? 'var(--green)' : s === 'handshaking' ? 'var(--yellow)' : 'var(--tx3)';

function span(text, color) {
  const s = document.createElement('span');
  s.textContent = text;
  if (color) s.style.color = color;
  return s;
}

function dirNode(p) {
  return span(p.direction === 'outbound' ? 'out' : 'in', dirColor(p.direction));
}
function stateNode(p) {
  const w = document.createElement('span');
  const dot = span('● ', stateColor(p.state));
  w.append(dot, document.createTextNode(p.state || '—'));
  return w;
}
function heightNode(p) {
  if (p.peer_height == null) return span('—', 'var(--tx3)');
  if (ourHeight != null && p.peer_height < ourHeight) {
    return span(`${num(p.peer_height)} · −${num(ourHeight - p.peer_height)}`, 'var(--yellow)');
  }
  return span(num(p.peer_height), 'var(--green)');
}

const COLS = [
  { key: 'addr', label: 'Address', width: 160, render: (r) => stacked(r.addr, r.network?.hostname), sort: (r) => r.addr },
  { key: 'network', label: 'Network', width: 130, render: (r) => stacked(r.network?.country || r.network?.country_code, r.network?.organization || (r.network?.asn ? `AS${r.network.asn}` : null)), sort: (r) => r.network?.country || '' },
  { key: 'dir', label: 'Direction', width: 64, render: dirNode, sort: (r) => r.direction },
  { key: 'state', label: 'State', width: 78, render: stateNode, sort: (r) => r.state },
  { key: 'height', label: 'Height', width: 84, align: 'right', render: heightNode, sort: (r) => r.peer_height ?? -1 },
  { key: 'in', label: 'Received', width: 80, align: 'right', render: (r) => stacked(bytes(r.bytes_in), rateText(r.rate_in)), sort: (r) => r.bytes_in ?? -1 },
  { key: 'out', label: 'Sent', width: 80, align: 'right', render: (r) => stacked(bytes(r.bytes_out), rateText(r.rate_out)), sort: (r) => r.bytes_out ?? -1 },
  { key: 'score', label: 'Penalty', width: 56, align: 'right', render: (r) => num(r.details?.effective_score ?? r.score), sort: (r) => r.details?.effective_score ?? r.score },
  { key: 'agent', label: 'Client', render: (r) => stacked(r.agent, r.version), sort: (r) => `${r.agent || ''} ${r.version || ''}` },
  { key: 'conn', label: 'Connected', width: 80, align: 'right', render: (r) => dur(r.connected_seconds), sort: (r) => r.connected_seconds },
];

function kv(label, value) {
  const r = document.createElement('div');
  r.className = 'ov-kv';
  const l = document.createElement('span');
  l.textContent = label;
  const v = document.createElement('span');
  if (value instanceof Node) v.append(value);
  else v.textContent = value ?? '—';
  r.append(l, v);
  return r;
}

function renderDetail(p) {
  const d = p.details || {};
  const n = p.network || {};
  const grid = document.createElement('div');
  grid.className = 'drawer-grid peer-detail';
  const copied = (value) => {
    if (!value) return 'Not advertised';
    const node = span(value);
    node.append(' ', copyBtn(value));
    return node;
  };
  const section = (title, description, rows) => {
    const node = document.createElement('section');
    const heading = document.createElement('h3');
    heading.className = 'micro-label';
    heading.textContent = title;
    const note = document.createElement('p');
    note.className = 'peer-note';
    note.textContent = description;
    node.append(heading, note, ...rows);
    return node;
  };
  const ago = (seconds) => seconds == null ? '—' : `${dur(seconds)} ago`;
  const date = (ms) => ms == null ? '—' : new Date(ms).toLocaleString();
  const featureNames = { 2: 'Local address', 3: 'Session / network', 4: 'REST API', 16: 'Node mode' };
  grid.append(section('Connection & traffic', 'Measured by this node. Traffic excludes the handshake; rates use successive snapshots.', [
    kv('Connected address', copied(p.addr)),
    kv('Direction', span(p.direction, dirColor(p.direction))),
    kv('State', span(p.state, stateColor(p.state))),
    kv('Connected for', dur(p.connected_seconds)),
    kv('Connection setup', d.connection_setup_ms == null ? '—' : `${num(d.connection_setup_ms)} ms (TCP + handshake)`),
    kv('Last message', ago(p.last_seen_seconds)),
    kv('Last useful activity', ago(d.last_progress_seconds)),
    kv('Received / sent', `${bytes(p.bytes_in)} / ${bytes(p.bytes_out)}`),
    kv('Receive / send rate', `${rateText(p.rate_in)} / ${rateText(p.rate_out)}`),
    kv('Traffic sampled', date(d.sampled_at_unix_ms)),
  ]));
  grid.append(section('Peer identity & mode', 'Reported by the peer during its handshake; names and settings are not verified.', [
    kv('Client', copied(p.agent)),
    kv('Advertised version', p.version || 'Not advertised'),
    kv('Node name', copied(p.node_name)),
    kv('Public address', copied(p.declared_address)),
    kv('Local address', copied(d.local_address)),
    kv('REST API URL', copied(p.rest_api_url)),
    kv('State mode', modeName(d.mode)),
    kv('Verifies transactions', d.mode ? (d.mode.verifies_transactions ? 'Yes' : 'No') : 'Not advertised'),
    kv('Block retention', retention(d.mode)),
    kv('NiPoPoW bootstrap', !d.mode ? 'Not advertised' : d.mode.nipopow_bootstrap == null ? 'Not indicated' : d.mode.nipopow_bootstrap === 1 ? 'KMZ17' : `Value ${d.mode.nipopow_bootstrap}`),
    kv('Network magic', d.network_magic),
    kv('Session ID', copied(d.session_id)),
    kv('Handshake features', d.feature_ids?.length ? d.feature_ids.map((id) => `${featureNames[id] || 'Unknown'} (${id})`).join(', ') : 'None advertised'),
  ]));
  grid.append(section('Sync & delivery health', 'Our observations of this connection. A lower penalty score is better.', [
    kv('Sync protocol', p.sync_version || '—'),
    kv('Observed height', heightNode(p)),
    kv('Height source', d.height_source === 'inferred_from_overlap' ? 'Inferred from shared headers' : d.height_source === 'reported_header' ? 'Reported in peer tip header' : 'Not observed'),
    kv('Chain relationship', chainLabel(d.chain_status)),
    kv('Last sync observation', ago(d.last_sync_seconds)),
    kv('Effective penalty', num(d.effective_score)),
    kv('Raw penalty', num(p.score)),
    kv('Consecutive delivery timeouts', num(d.delivery_failure_streak)),
    kv('Download preference', d.preferred_for_downloads == null ? '—' : d.preferred_for_downloads ? 'Preferred by connection health' : 'Outside preferred set'),
  ]));
  const coordinates = n.latitude != null && n.longitude != null ? `${n.latitude.toFixed(2)}, ${n.longitude.toFixed(2)}` : null;
  const dbName = (name, built) => name ? `${name}${built ? ` · ${new Date(built * 1000).toLocaleDateString()}` : ''}` : '—';
  grid.append(section('Network & approximate location', 'IP database estimates describe the network endpoint, not the operator. Hostnames are reverse DNS records.', [
    kv('IP address', n.ip),
    kv('Address type', n.ip_version ? `${n.ip_version} · ${(n.scope || '').replaceAll('_', ' ')}` : null),
    kv('Hostname', n.hostname || lookupStatus(n.hostname_status)),
    kv('Hostname checked', date(n.hostname_checked_at_unix_ms)),
    kv('Country', n.country ? `${n.country}${n.country_code ? ` (${n.country_code})` : ''}` : n.country_code || lookupStatus(n.geo_status)),
    kv('Continent', n.continent),
    kv('Region / city', [n.region, n.city].filter(Boolean).join(' / ') || '—'),
    kv('Time zone', n.time_zone),
    kv('Approximate coordinates', coordinates),
    kv('Accuracy radius', n.accuracy_radius_km == null ? '—' : `${num(n.accuracy_radius_km)} km`),
    kv('ASN', n.asn == null ? lookupStatus(n.asn_status) : `AS${n.asn}`),
    kv('Network organization', n.organization),
    kv('Network prefix', n.network_cidr),
    kv('Location database / built', dbName(n.geo_database, n.geo_database_built_at_unix_seconds)),
    kv('ASN database / built', dbName(n.asn_database, n.asn_database_built_at_unix_seconds)),
  ]));
  return grid;
}

export function mount(el) {
  root = el;
  el.innerHTML = `
    <div class="pg-head">
      <div>
        <h1 class="pg-title">Peers</h1>
        <p class="pg-description">The connections keeping your node in touch with the network.</p>
        <span class="pg-count micro-label" data-count></span>
      </div>
      <button class="btn btn--ghost" type="button" data-refresh>Refresh peers</button>
    </div>
    <div class="banner banner--warn" data-error role="status" hidden></div>
    <p class="peer-note" data-lookup-note hidden></p>
    <p class="peer-note" data-db-attribution hidden><a href="https://db-ip.com" target="_blank" rel="noopener noreferrer">IP Geolocation by DB-IP</a> · <a href="https://creativecommons.org/licenses/by/4.0/" target="_blank" rel="noopener noreferrer">CC BY 4.0</a> · Locations are approximate.</p>
    <div class="comp" data-comp></div>
    <div class="filter-bar">
      <label class="filter-bar__search">Find a peer<input class="input" type="search" data-search placeholder="Address, hostname, country, network, client or node name" autocomplete="off"></label>
      <label>Direction<select class="select" data-direction><option value="all">All connections</option><option value="outbound">Outbound</option><option value="inbound">Inbound</option></select></label>
      <button class="btn btn--ghost" type="button" data-clear hidden>Clear filters</button>
    </div>
    <div class="list-meta"><span data-results role="status">Loading peer connections…</span><span data-updated></span></div>
    <div data-table></div>`;
  table = makeTable(el.querySelector('[data-table]'), COLS, {
    rowKey: (r) => r.addr,
    renderDetail,
    initialSort: { key: 'conn', dir: -1 },
    label: 'Network peers',
    emptyMessage: () => lastPeers.length ? 'No peers match these filters. Try another address or connection direction.' : 'No peer connections yet. The node will keep looking for peers.',
  });
  el.querySelector('[data-search]').addEventListener('input', applyFilters);
  el.querySelector('[data-direction]').addEventListener('change', applyFilters);
  el.querySelector('[data-clear]').addEventListener('click', () => {
    el.querySelector('[data-search]').value = '';
    el.querySelector('[data-direction]').value = 'all';
    el.querySelector('[data-search]').focus();
    applyFilters();
  });
  el.querySelector('[data-refresh]').addEventListener('click', fullRefresh);
}

function applyFilters() {
  const query = root.querySelector('[data-search]').value.trim().toLowerCase();
  const direction = root.querySelector('[data-direction]').value;
  const filtered = lastPeers.filter((p) =>
    (direction === 'all' || p.direction === direction) &&
    peerMatches(p, query),
  );
  root.querySelector('[data-clear]').hidden = !query && direction === 'all';
  root.querySelector('[data-results]').textContent = `${filtered.length} of ${lastPeers.length} peers`;
  table.update(filtered);
}

function bar(segments) {
  const w = document.createElement('div');
  w.className = 'distbar';
  for (const s of segments) {
    const d = document.createElement('div');
    d.style.width = `${Math.max(0, s.frac * 100)}%`;
    d.style.background = s.color;
    w.append(d);
  }
  return w;
}

function compCell(title, body) {
  const c = document.createElement('div');
  c.className = 'comp__cell';
  const h = document.createElement('div');
  h.className = 'micro-label';
  h.textContent = title;
  c.append(h, body);
  return c;
}

function renderComp(peers) {
  const host = root.querySelector('[data-comp]');
  host.replaceChildren();
  const total = peers.length || 1;
  const out = peers.filter((p) => p.direction === 'outbound').length;
  const inn = peers.filter((p) => p.direction === 'inbound').length;
  const conn = peers.filter((p) => p.state === 'connected' || p.state === 'active').length;
  const hs = peers.filter((p) => p.state === 'handshaking').length;
  const other = peers.length - conn - hs;

  // direction
  const dirBody = document.createElement('div');
  const outValue = document.createElement('div');
  outValue.className = 'comp__value';
  outValue.textContent = num(out);
  dirBody.append(outValue);
  dirBody.append(
    bar([
      { frac: out / total, color: 'var(--blue)' },
      { frac: inn / total, color: 'var(--purple)' },
    ]),
  );
  const dl = document.createElement('div');
  dl.className = 'comp__legend';
  dl.textContent = `out ${out} · in ${inn}`;
  dirBody.append(dl);

  // state
  const stBody = document.createElement('div');
  const activeValue = document.createElement('div');
  activeValue.className = 'comp__value';
  activeValue.textContent = num(conn);
  stBody.append(activeValue);
  stBody.append(
    bar([
      { frac: conn / total, color: 'var(--green)' },
      { frac: hs / total, color: 'var(--yellow)' },
      { frac: other / total, color: 'var(--tx3)' },
    ]),
  );
  const sl = document.createElement('div');
  sl.className = 'comp__legend';
  sl.textContent = `connected ${conn} · handshaking ${hs}${other ? ` · other ${other}` : ''}`;
  stBody.append(sl);

  // agents
  const counts = Object.create(null);
  for (const p of peers) {
    const a = (p.agent || 'unknown').split('/').slice(0, 2).join('/');
    counts[a] = (counts[a] || 0) + 1;
  }
  const agBody = document.createElement('div');
  agBody.className = 'comp__agents';
  Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 3)
    .forEach(([a, n]) => {
      const r = document.createElement('div');
      r.className = 'ov-kv';
      const l = document.createElement('span');
      l.textContent = a;
      const v = document.createElement('span');
      v.textContent = String(n);
      r.append(l, v);
      agBody.append(r);
    });

  host.append(compCell('Outbound connections', dirBody), compCell('Active connections', stBody), compCell('Connected clients', agBody));
}

function scheduleRefresh(delayMs) {
  if (refreshTimer) clearTimeout(refreshTimer);
  refreshTimer = setTimeout(() => {
    refreshTimer = null;
    fullRefresh();
  }, delayMs);
}

async function fullRefresh() {
  if (!root || refreshing) return;
  refreshing = true;
  const refresh = root.querySelector('[data-refresh]');
  refresh.disabled = true;
  refresh.textContent = 'Refreshing…';
  try {
    const [peers, status] = await Promise.all([api.peers(), api.status()]);
    if (status) ourHeight = status.best_header_height ?? null;
    const error = root.querySelector('[data-error]');
    if (!Array.isArray(peers)) {
      error.textContent = 'Could not refresh peers. Showing the last available data; use Refresh peers to try again.';
      error.hidden = false;
      return;
    }
    error.hidden = true;
    const list = sampleTraffic(peers);
    lastPeers = list;
    const lookupNote = root.querySelector('[data-lookup-note]');
    lookupNote.textContent = peerLookupNote(list);
    lookupNote.hidden = !lookupNote.textContent;
    root.querySelector('[data-db-attribution]').hidden = !list.some((p) =>
      /db-?ip/i.test(`${p.network?.geo_database || ''} ${p.network?.asn_database || ''}`));
    root.querySelector('[data-count]').textContent = `${list.length} peers · ${list.filter((p) => p.state === 'active' || p.state === 'connected').length} active`;
    renderComp(list);
    applyFilters();
    lastFullAt = Date.now();
    root.querySelector('[data-updated]').textContent = `Updated ${new Date(lastFullAt).toLocaleTimeString()}`;
  } finally {
    refreshing = false;
    refresh.disabled = false;
    refresh.textContent = 'Refresh peers';
  }
}

export function onShow() {
  peersWs.start();
  fullRefresh();
}

export function onHide() {
  peersWs.stop();
  trafficSamples.clear();
  if (refreshTimer) {
    clearTimeout(refreshTimer);
    refreshTimer = null;
  }
}

export async function onSlow() {
  if (peersWs.isConnected() && Date.now() - lastFullAt < HTTP_FALLBACK_MS) return;
  await fullRefresh();
}
