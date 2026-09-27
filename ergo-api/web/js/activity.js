import { api } from './api-client.js';
import { getApiKey, subscribe, promptAuthorize, CONFIGURE_API_KEY } from './auth.js';
import { ActivityBuffer, currentIssues, groupRecords, filterRecords, exportEvidence } from './activity-model.js';
import { blockRejectionState } from './node-guidance.js';

const buffer = new ActivityBuffer();
const PAGE_SIZE = 25;
let root, active = false, inFlight = false, generation = 0, key = '', status = null, indexer = null;
let statusAt = 0, indexAt = 0, reachable = false, indexReachable = false, logAt = 0, error = '', authError = false;
let paused = false, frozen = [], frozenMeta = null, frozenAt = 0, pending = 0, page = 0;
const filters = { query: '', level: 'highlights', subsystem: '', minutes: '', routine: false };
const $ = (selector) => root?.querySelector(selector);
const text = (selector, value) => { const el = $(selector); if (el && el.textContent !== value) el.textContent = value; };
const node = (tag, className, content) => {
  const el = document.createElement(tag); if (className) el.className = className;
  if (content !== undefined) el.textContent = content; return el;
};
const utc = (ms) => Number.isFinite(ms) && ms > 0 ? new Date(ms).toISOString().replace('T', ' ').replace('Z', ' UTC') : 'Time unavailable';
const count = (n) => n.toLocaleString();
const view = () => paused ? frozen : buffer.records;
const meta = () => paused ? frozenMeta : buffer.meta;
const selectedRecords = () => filterRecords(view(), filters, paused ? frozenAt : Date.now());

export function mount(el) {
  root = el;
  root.innerHTML = `
    <div class="pg-head pg-head--flush activity-head">
      <div><div class="ov-eyebrow">NODE OPERATIONS</div><h1 class="pg-title">Activity &amp; logs</h1>
      <p class="ov-intro">Current issues, recent events and the evidence behind them.</p></div>
      <div class="activity-actions"><button class="btn" type="button" data-pause aria-pressed="false">Pause updates</button><button class="btn" type="button" data-export disabled>Download evidence</button></div>
    </div>
    <section class="activity-current" aria-labelledby="activity-current-title">
      <div class="activity-section-head"><h2 id="activity-current-title">Current conditions</h2><span data-health-freshness>Waiting for status</span></div>
      <div data-current></div><p class="activity-note" data-index-status></p>
    </section>
    <section class="activity-history" aria-labelledby="activity-history-title">
      <div class="activity-section-head"><div><h2 id="activity-history-title">Recent history</h2><p class="activity-note">Matching messages are grouped within five minutes. Counts cover retained records. Times are UTC.</p></div><span class="activity-live" data-live>Connecting</span></div>
      <div class="activity-notice" data-access hidden><p data-access-note></p><button type="button" class="btn btn--primary" data-authorize>Authorize to view logs</button></div>
      <p class="activity-notice" data-error hidden></p>
      <div class="activity-metrics" aria-label="Retained history summary"><div><strong data-record-count>—</strong><span>records in view</span></div><div><strong data-error-count>—</strong><span>error records</span></div><div><strong data-repeat-count>—</strong><span>repeats grouped</span></div></div>
      <form class="activity-filters" aria-label="Filter activity">
        <label class="activity-search">Search evidence<input class="input" name="query" type="search" autocomplete="off" placeholder="Message, code, peer, block ID…" maxlength="256"></label>
        <label>Show<select class="input" name="level"><option value="highlights">Warnings &amp; recoveries</option><option value="">All severities</option><option value="attention">Warnings &amp; errors</option><option value="ERROR">Errors</option><option value="WARN">Warnings</option><option value="INFO">Information</option></select></label>
        <label>Subsystem<select class="input" name="subsystem"><option value="">All subsystems</option>${['Node', 'Network', 'Sync', 'Validation', 'Storage', 'Index', 'Mempool', 'Mining', 'Wallet', 'API'].map(s => `<option>${s}</option>`).join('')}</select></label>
        <label>Time window<select class="input" name="minutes"><option value="">All retained</option><option value="15">Last 15 minutes</option><option value="60">Last hour</option><option value="1440">Last 24 hours</option></select></label>
        <label class="activity-check"><input type="checkbox" name="routine"> Include heartbeat &amp; progress</label><button type="button" class="btn btn--ghost" data-reset>Reset filters</button>
      </form>
      <div class="activity-results-head"><span data-results role="status" aria-live="polite"></span><span data-pending></span></div>
      <div class="activity-list" data-list></div>
      <div class="activity-pagination"><button class="btn" type="button" data-prev>Previous</button><span data-page></span><button class="btn" type="button" data-next>Next</button></div>
      <p class="activity-note" data-retention></p>
      <details class="activity-about"><summary>About this history</summary><p>This view retains up to 2,048 recent INFO, WARN and ERROR records (4 MiB) on the node for this process session. Restarting the node clears this buffer. Pausing freezes the history view; current conditions continue to refresh.</p><p>Grouping preserves each retained record. Timing and retry counters may differ within a group; peer addresses, block IDs and reasons remain distinct. Log severity alone does not establish an active incident or a recovery.</p><p>Full rotated logs and automatic incident snapshots remain in the node’s configured log and incident directories. This view shortens oversized fields and redacts named credential fields; exports can still contain peer addresses and operational details. DEBUG and TRACE output is available in the file logs when enabled.</p></details>
    </section><p class="activity-feedback" role="status" aria-live="polite" data-feedback></p>`;
  $('form').onsubmit = e => e.preventDefault();
  $('form').addEventListener('input', e => {
    const input = e.target; if (!(input.name in filters)) return;
    filters[input.name] = input.type === 'checkbox' ? input.checked : input.value;
    page = 0; renderHistory();
  });
  $('[data-reset]').onclick = () => {
    Object.assign(filters, { query: '', level: 'highlights', subsystem: '', minutes: '', routine: false });
    $('form').reset(); page = 0; renderHistory();
  };
  $('[data-authorize]').onclick = promptAuthorize;
  $('[data-pause]').onclick = () => setPaused(!paused);
  $('[data-export]').onclick = () => download(selectedRecords(), 'activity');
  $('[data-prev]').onclick = () => { setPaused(true, false); page--; renderHistory(); };
  $('[data-next]').onclick = () => { setPaused(true, false); page++; renderHistory(); };
  key = getApiKey();
  subscribe(s => {
    const current = getApiKey();
    if (current !== key || ['none', 'invalid', 'unconfigured'].includes(s)) {
      key = current; generation++; scrub();
      authError = true;
      error = s === 'unconfigured' ? CONFIGURE_API_KEY : s === 'invalid' ? 'The operator API key was rejected. Authorize again to view logs.' : 'Log history requires the operator API key. Current conditions remain available.';
      renderHistory();
    }
  });
  window.addEventListener('pagehide', () => { generation++; scrub(); });
}

function scrub() {
  buffer.clear(); frozen = []; frozenMeta = null; pending = 0; paused = false; page = 0; logAt = 0;
  const list = $('[data-list]');
  list?.replaceChildren(); if (list) delete list.dataset.signature;
  text('[data-feedback]', '');
}
export function onShow() { active = true; renderCurrent(); renderHistory(); }
export function onHide() { active = false; generation++; scrub(); renderHistory(); }
export function onFast(data) {
  reachable = !!data.reachable;
  if (data.status) { status = data.status; statusAt = Date.now(); }
  renderCurrent();
}

export async function onSlow() {
  if (!active || inFlight) return;
  inFlight = true;
  const ticket = generation;
  try {
    const index = await api.indexerStatus();
    if (!active || ticket !== generation) return;
    indexReachable = typeof index?.status === 'string';
    if (indexReachable) { indexer = index; indexAt = Date.now(); }
    renderCurrent();
    if (!getApiKey()) { renderHistory(); return; }
    for (let n = 0; n < 8; n++) {
      const response = await api.activity(buffer.session, buffer.cursor);
      if (!active || ticket !== generation) return;
      if (!response?.ok) {
        authError = response?.status === 403;
        if (authError) scrub();
        error = response?.status === 404 ? 'This node version does not provide log history.' : authError ? 'Authorize with the operator API key to view logs.' : 'Log history is unavailable. Retained records are shown; the page will retry.';
        break;
      }
      error = ''; authError = false;
      const oldSession = buffer.session;
      const added = buffer.ingest(response.data);
      // A restart invalidates paused evidence too; never mix process sessions.
      if ((oldSession && oldSession !== buffer.session) || response.data.reset) {
        paused = false; frozen = []; frozenMeta = null; pending = 0; page = 0;
        status = null; statusAt = 0; indexer = null; indexAt = 0; reachable = false; indexReachable = false;
        renderCurrent();
      }
      if (paused) pending += added;
      logAt = Date.now();
      if (!response.data.hasMore) break;
    }
  } catch (e) { error = e.message || 'Log history could not be read.'; }
  finally { inFlight = false; if (active) renderHistory(); }
}

function setPaused(value, render = true) {
  if (value && !paused) { frozen = [...buffer.records]; frozenMeta = buffer.meta ? { ...buffer.meta } : null; frozenAt = Date.now(); pending = 0; }
  if (!value) { frozen = []; frozenMeta = null; pending = 0; page = 0; }
  paused = value; if (render) renderHistory(); else paintControls();
}
function paintControls() {
  text('[data-pause]', paused ? 'Resume live history' : 'Pause updates');
  $('[data-pause]')?.setAttribute('aria-pressed', String(paused));
  text('[data-pending]', paused && pending ? `${count(pending)} new records · resume to view` : '');
  text('[data-live]', paused ? 'History paused' : error ? 'Not updating' : logAt ? 'Live history' : 'Waiting for logs');
}

function renderCurrent() {
  if (!root) return;
  const stale = !reachable || !statusAt || Date.now() - statusAt > 15000 || status?.snapshot_age_ms > 15000;
  const indexStale = !indexReachable || !indexAt || Date.now() - indexAt > 15000;
  text('[data-health-freshness]', stale ? 'Status unconfirmed · last known conditions' : 'Live status');
  const host = $('[data-current]');
  const issues = currentIssues(status, indexer);
  const fingerprint = JSON.stringify([statusAt > 0, stale, indexStale, issues, blockRejectionState(status), status?.last_block_apply_error?.block_id, status?.best_full_block_height]);
  if (host.dataset.fingerprint !== fingerprint) {
    const open = new Set([...host.querySelectorAll('details[open]')].map(el => el.dataset.issue));
    host.dataset.fingerprint = fingerprint; host.replaceChildren();
    if (issues.length) {
      for (const issue of issues) {
        const card = node('details', 'activity-issue'); card.dataset.tone = issue.severity;
        card.dataset.issue = issue.id; card.open = open.has(issue.id);
        const issueStale = ['index', 'repair', 'skipped'].includes(issue.id) ? indexStale : stale;
        const summary = node('summary'); summary.append(node('span', 'activity-dot'), node('strong', '', issue.title), node('span', 'activity-badge', issueStale ? 'Last reported' : 'Needs attention'));
        const body = node('div', 'activity-issue-body'); body.append(node('p', '', issue.detail), node('p', 'activity-note', issue.action));
        card.append(summary, body); host.append(card);
      }
    } else host.append(node('p', 'activity-clear', stale ? 'A fresh node status is needed before current conditions can be assessed.' : 'No active processing, storage or connectivity issue is reported.'));
    if (blockRejectionState(status) === 'historical') {
      const recovered = node('details', 'activity-issue'); recovered.dataset.tone = 'ok';
      recovered.dataset.issue = 'recovered'; recovered.open = open.has('recovered');
      const summary = node('summary'); summary.append(node('span', 'activity-dot'), node('strong', '', 'Chain advanced beyond the last rejected block'), node('span', 'activity-badge', stale ? 'Last reported' : 'Recovered'));
      const body = node('div', 'activity-issue-body'); const rejection = status.last_block_apply_error;
      body.append(node('p', '', `Rejected height ${rejection.height}; applied height ${status.best_full_block_height}. This confirms progress beyond that rejection, not validation of the rejected block.`), node('pre', 'activity-raw', JSON.stringify(rejection, null, 2)));
      recovered.append(summary, body); host.append(recovered);
    }
  }
  text('[data-index-status]', indexStale ? 'Search index status unavailable. Any retained index condition is last reported, not confirmed current.' : `Search index: ${indexer.status === 'caughtUp' ? 'caught up' : indexer.status || 'unknown'}.`);
}

function renderHistory() {
  if (!root) return;
  paintControls();
  const needsAuth = authError || !getApiKey();
  $('[data-access]').hidden = !needsAuth;
  text('[data-access-note]', needsAuth ? error || 'Authorize with the operator API key to view retained logs.' : '');
  $('[data-error]').hidden = !error || needsAuth;
  text('[data-error]', error);
  const selected = selectedRecords();
  const groups = groupRecords(selected);
  const pages = Math.max(1, Math.ceil(groups.length / PAGE_SIZE));
  page = Math.max(0, Math.min(page, pages - 1));
  text('[data-record-count]', logAt ? count(selected.length) : '—');
  text('[data-error-count]', logAt ? count(selected.filter(r => r.level === 'ERROR').length) : '—');
  text('[data-repeat-count]', logAt ? count(selected.length - groups.length) : '—');
  text('[data-results]', `${count(groups.length)} ${groups.length === 1 ? 'group' : 'groups'} · ${count(selected.length)} matching ${selected.length === 1 ? 'record' : 'records'}`);
  text('[data-page]', `Page ${page + 1} of ${pages}`);
  $('[data-prev]').disabled = page === 0; $('[data-next]').disabled = page >= pages - 1;
  $('[data-export]').disabled = !selected.length || needsAuth;
  // A paused page's DOM is stable while incoming records update the counter.
  // Filters/navigation explicitly change the signature and rebuild the list.
  const signature = JSON.stringify([buffer.session, page, filters, groups.map(g => [g.id, g.lastSeq])]);
  const host = $('[data-list]');
  if (host.dataset.signature !== signature) {
    host.dataset.signature = signature; host.replaceChildren();
    for (const group of groups.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE)) host.append(groupRow(group));
    if (!groups.length) host.append(node('p', 'activity-empty', needsAuth ? 'Authorize to inspect recent node activity.' : !logAt ? 'Waiting for the first log response.' : view().length ? 'No records match these filters. Try another time window or include routine progress.' : 'No log records are retained in this node session yet.'));
  }
  const m = meta(); const notes = [];
  if (m) {
    const records = view();
    notes.push(`${count(records.length)} records held in this view${records.length ? ` · ${utc(Math.min(...records.map(r => r.unixMs)))} to ${utc(Math.max(...records.map(r => r.unixMs)))}` : ''}.`);
    if (BigInt(m.oldestSeq) > 1n || buffer.trimmed) notes.push('Older records have left the bounded history. Full evidence may remain in the file logs.');
    if (buffer.gap) notes.push('History gap: some records were evicted between requests.');
    if (BigInt(m.droppedTotal || '0') > 0n) notes.push(`${m.droppedTotal} records were not captured while the history buffer was busy.`);
    if (buffer.restarted) notes.push('The node session changed or its cursor reset; previous-session records were cleared.');
    if (m.hasMore) notes.push('Catching up with retained history…');
  }
  if (logAt) notes.push(`Last successful history read: ${utc(logAt)}.`);
  text('[data-retention]', notes.join(' '));
}

function groupRow(group) {
  const row = node('details', 'activity-row'); row.dataset.level = group.level; row.dataset.state = group.state;
  const summary = node('summary');
  const severity = node('span', 'activity-severity', group.level === 'ERROR' ? 'Error' : group.level === 'WARN' ? 'Warning' : group.state === 'recovered' ? 'Recovered' : 'Info');
  const content = node('span', 'activity-row-copy'); content.append(node('strong', '', group.title), node('span', 'activity-row-meta', [group.subsystem, group.code].filter(Boolean).join(' · ')));
  const occurrences = node('span', 'activity-occurrences', group.records.length > 1 ? `×${count(group.records.length)}` : '1 event');
  occurrences.title = 'Occurrences among retained records';
  const time = node('time', '', utc(group.last).replace(/\.\d{3} UTC$/, ''));
  if (group.last > 0) time.dateTime = new Date(group.last).toISOString();
  time.title = group.records.length > 1 ? `${utc(group.first)} — ${utc(group.last)}` : utc(group.last);
  summary.append(severity, content, occurrences, time); row.append(summary);
  let built = false;
  row.addEventListener('toggle', () => {
    if (!row.open) return;
    // Freeze before any timer can reorder an open item or steal keyboard focus.
    setPaused(true, false);
    if (built) return; built = true;
    const body = node('div', 'activity-evidence');
    body.append(node('p', 'activity-note', `First seen: ${utc(group.first)} · Last seen: ${utc(group.last)} · ${count(group.records.length)} retained occurrence${group.records.length === 1 ? '' : 's'}.`));
    if (group.state === 'recorded' && group.level !== 'INFO') body.append(node('p', 'activity-note', 'This is a historical log record. Check Current conditions above to determine whether a related issue is still reported.'));
    if (group.truncated) body.append(node('p', 'activity-notice', 'This record was shortened for the bounded history. Consult the file log for full evidence.'));
    const actions = node('div', 'activity-actions');
    const copy = node('button', 'btn', 'Copy evidence'); copy.type = 'button';
    copy.onclick = async () => {
      try { await navigator.clipboard.writeText(exportEvidence(group.records, exportMeta())); text('[data-feedback]', 'Group evidence copied.'); }
      catch { text('[data-feedback]', 'Clipboard unavailable. Download the evidence instead.'); }
    };
    const save = node('button', 'btn', 'Download group'); save.type = 'button'; save.onclick = () => download(group.records, `activity-${group.id}`);
    actions.append(copy, save); body.append(actions);
    const preview = group.records.slice(-20);
    if (group.records.length > preview.length) body.append(node('p', 'activity-note', `Showing the latest ${preview.length} occurrences below. Copy or download includes all ${group.records.length} retained occurrences.`));
    body.append(node('pre', 'activity-raw', preview.map(r => JSON.stringify(r, null, 2)).join('\n\n')));
    row.append(body);
  });
  return row;
}

function exportMeta() {
  return { exportedAt: new Date().toISOString(), sessionId: buffer.session, retention: meta(), filters: { ...filters }, gap: buffer.gap, clientTrimmed: buffer.trimmed, paused, pausedAt: paused ? frozenAt : null, lastSuccessfulRead: logAt, currentStatus: status, currentStatusAt: statusAt, statusReachable: reachable, indexer, indexStatusAt: indexAt, indexReachable };
}
function download(records, name) {
  if (!getApiKey() || !records.length) return;
  const url = URL.createObjectURL(new Blob([exportEvidence(records, exportMeta())], { type: 'application/x-ndjson' }));
  const link = node('a'); link.href = url; link.download = `${name}-${new Date().toISOString().replace(/[:.]/g, '-')}.ndjson`;
  document.body.append(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
  text('[data-feedback]', `Downloaded ${count(records.length)} retained records with session and status context.`);
}
