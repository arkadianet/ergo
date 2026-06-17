// Voting page: shows the protocol parameters the operator can vote on (with
// current value + allowed range), and — for a mining node with an API key set —
// lets the operator set vote targets. Each block carries at most two parameter
// votes (consensus rule 212, ParamVotesCount=2); a parameter changes only once
// more than half the blocks in the voting epoch carry its vote (Scala
// VotingSettings.changeApproved = count > votingLength/2; >512 of 1024 on
// mainnet), and then moves exactly one step per epoch within its range. When
// more than two parameters are targeted the node votes lowest-id-first and
// skips any already at target or at a bound, so the rest follow in later epochs.
//
// Reads `GET /api/v1/votes` (open). Writes `POST /api/v1/votes` (auth-gated by
// the operator's api_key; rejected 409 when the node is not mining). The write
// REPLACES the full target set.
import { api } from './api-client.js';
import { num } from './format.js';
import { getApiKey, subscribe } from './auth.js';
import { sparkline } from './sparkline.js';

let root = null;
// Signature of the rows currently built (see `rowsKey`). The 4s poll only
// rebuilds inputs when this changes; otherwise it refreshes read-only cells so
// the operator's in-progress edits are never clobbered.
let builtKey = null;
// True while the last poll's fetch failed, so a recovered fetch can clear the
// "Could not load voting data." error without clobbering a save result.
let loadFailed = false;
// Unsubscribe handle for the auth-state gating of the Save button.
let votingAuthUnsub = null;

function cell(text, cls, label) {
  const td = document.createElement('td');
  if (cls) td.className = cls;
  if (label) td.dataset.label = label; // mobile reflow label (.table)
  td.textContent = text;
  return td;
}

function setStatus(msg, kind) {
  const el = root.querySelector('[data-status]');
  if (!el) return;
  el.textContent = msg || '';
  // Color via class (not inline style); the span is aria-live so screen
  // readers announce save/validation results.
  el.className =
    'vt-status' + (kind === 'ok' ? ' vt-status--ok' : kind === 'err' ? ' vt-status--err' : '');
}

// Rows to render = every votable parameter, PLUS any configured vote whose
// parameter is not currently in the votable set (e.g. subblocksPerBlock before
// it becomes active). Because the save does a full replace, a configured target
// without a rendered input would be silently dropped — so we always render it.
function unionRows(params, configured) {
  const byId = new Map(params.map((p) => [p.id, p]));
  const rows = params.map((p) => ({
    id: p.id,
    name: p.name,
    description: p.description,
    current: p.current,
    min: p.min,
    max: p.max,
    step: p.step,
    votable: true,
  }));
  for (const c of configured) {
    if (!byId.has(c.parameterId)) {
      rows.push({ id: c.parameterId, name: c.name, votable: false });
    }
  }
  return rows;
}

// Rebuild key: the rendered id set PLUS the per-row metadata that shapes the
// row (votability, range, step). Excludes `current` (that changes every block
// and is handled by the lighter refreshCells). So when a parameter's metadata
// changes without an id-set change — e.g. id 9 becoming active, or a step/range
// update — the rows rebuild instead of showing stale "(not active)" / bounds.
function rowsKey(params, configured) {
  return unionRows(params, configured)
    .map((r) => `${r.id}:${r.votable ? 1 : 0}:${r.min}:${r.max}:${r.step}`)
    .join(',');
}

function buildRows(params, configured) {
  const tbody = root.querySelector('[data-rows]');
  tbody.replaceChildren();
  const cfg = new Map(configured.map((c) => [c.parameterId, c.target]));
  for (const r of unionRows(params, configured)) {
    const tr = document.createElement('tr');
    tr.dataset.id = String(r.id);
    const nameTd = document.createElement('td');
    nameTd.dataset.label = 'Parameter';
    const nameLine = document.createElement('div');
    nameLine.className = 'vt-name';
    nameLine.textContent = r.name;
    if (!r.votable) {
      // Configured but not in the current votable set — keep it, but flag it.
      const hint = document.createElement('span');
      hint.className = 'vt-inactive';
      hint.textContent = ' (not active)';
      nameLine.append(hint);
    }
    nameTd.append(nameLine);
    // Operator-facing explanation of what the vote does (from the API). Always
    // visible (not a hover tooltip) so the implication is clear on any device.
    if (r.description) {
      const desc = document.createElement('div');
      desc.className = 'vt-desc';
      desc.textContent = r.description;
      nameTd.append(desc);
    }
    tr.append(
      nameTd,
      cell(num(r.current), 'table__num vt-current', 'Current'),
      cell(r.votable ? `${num(r.min)} – ${num(r.max)}` : '—', 'table__num vt-range', 'Range'),
      cell(num(r.step), 'table__num', 'Step'),
    );
    // configured (live) target cell
    const live = document.createElement('td');
    live.className = 'table__num vt-live';
    live.dataset.label = 'Voting';
    live.textContent = cfg.has(r.id) ? num(cfg.get(r.id)) : '—';
    tr.append(live);
    // editable target input
    const inputTd = document.createElement('td');
    inputTd.dataset.label = 'Target';
    const input = document.createElement('input');
    input.type = 'number';
    input.className = 'input vt-input';
    if (r.votable) {
      input.min = String(r.min);
      input.max = String(r.max);
      input.step = String(r.step);
    }
    input.placeholder = 'no vote';
    input.setAttribute('aria-label', `${r.name} vote target`);
    input.dataset.id = String(r.id);
    input.dataset.name = r.name;
    if (cfg.has(r.id)) input.value = String(cfg.get(r.id));
    inputTd.append(input);
    tr.append(inputTd);
    tbody.append(tr);
  }
  builtKey = rowsKey(params, configured);
}

// Light per-poll refresh: update the read-only current + live-target cells
// without touching the operator's in-progress input edits.
function refreshCells(params, configured) {
  const cfg = new Map(configured.map((c) => [c.parameterId, c.target]));
  const curById = new Map(params.map((p) => [p.id, p.current]));
  for (const tr of root.querySelectorAll('tr[data-id]')) {
    const id = Number(tr.dataset.id);
    const cur = tr.querySelector('.vt-current');
    if (cur && curById.has(id)) cur.textContent = num(curById.get(id));
    const live = tr.querySelector('.vt-live');
    if (live) live.textContent = cfg.has(id) ? num(cfg.get(id)) : '—';
  }
}

async function save() {
  if (!getApiKey()) {
    setStatus('Set your api_key via the Authorize chip to change votes.', 'err');
    return;
  }
  // Collect non-blank inputs as the full desired set (replace semantics).
  const votes = [];
  const invalid = [];
  for (const input of root.querySelectorAll('.vt-input')) {
    const raw = input.value.trim();
    if (raw === '') continue;
    const label = input.dataset.name || `id ${input.dataset.id}`;
    const target = Number(raw);
    if (!Number.isFinite(target)) {
      invalid.push(`${label} is not a number`);
      continue;
    }
    // A vote can only move a parameter within its allowable [min, max] — a
    // target beyond that can never be reached, so reject it here (the node
    // enforces the same bound authoritatively). Bounds present only on votable
    // rows; non-votable (e.g. subblocks pre-activation) inputs have none.
    const min = input.min === '' ? null : Number(input.min);
    const max = input.max === '' ? null : Number(input.max);
    if ((min !== null && target < min) || (max !== null && target > max)) {
      invalid.push(`${label} must be ${num(min)} – ${num(max)}`);
      continue;
    }
    votes.push({ parameterId: Number(input.dataset.id), target });
  }
  if (invalid.length) {
    setStatus(`Out of allowable range — ${invalid.join('; ')}.`, 'err');
    return;
  }
  setStatus('Saving…', 'muted');
  const res = await api.setVotes(votes);
  if (res.ok) {
    setStatus(votes.length ? `Saved ${votes.length} vote target(s).` : 'Cleared all votes.', 'ok');
    await load();
    return;
  }
  if (res.status === 403) {
    setStatus('Rejected (403): missing or invalid api_key — use the Authorize chip.', 'err');
  } else if (res.status === 409) {
    setStatus('Node is not mining — vote targets have no effect until mining is enabled.', 'err');
  } else {
    setStatus(`Rejected (${res.status || 'network error'}): ${res.detail || 'could not set votes'}`, 'err');
  }
}

export function mount(el) {
  root = el;
  builtKey = null;
  loadFailed = false;
  el.innerHTML = `
    <div class="pg-head">
      <div>
        <h1 class="pg-title">Voting</h1>
        <span class="pg-count micro-label" data-meta></span>
      </div>
    </div>
    <div class="vt-rules" aria-label="Voting rules">
      <div class="vt-rule">
        <span class="micro-label">Targets</span>
        <b>Within range</b>
        <span>Blank clears a vote; saves replace the full target set.</span>
      </div>
      <div class="vt-rule">
        <span class="micro-label">Authority</span>
        <b>api_key + mining</b>
        <span>Viewing is public; writes require an authorized mining node.</span>
      </div>
      <div class="vt-rule">
        <span class="micro-label">Per block</span>
        <b>Two votes</b>
        <span>Extra targets wait while lower numbered parameters settle.</span>
      </div>
      <div class="vt-rule">
        <span class="micro-label">Per epoch</span>
        <b>One step</b>
        <span>Changes need more than half of epoch blocks carrying the vote.</span>
      </div>
    </div>
    <table class="table">
      <thead><tr>
        <th>Parameter</th><th class="table__num">Current</th><th class="table__num">Range</th>
        <th class="table__num">Step</th><th class="table__num">Voting</th><th>Target</th>
      </tr></thead>
      <tbody data-rows></tbody>
    </table>
    <div class="vt-actions">
      <button class="btn btn--primary" data-save type="button">Save votes</button>
      <button class="btn btn--danger" data-clear type="button">Clear all</button>
      <span class="vt-status" data-status aria-live="polite"></span>
    </div>
    <div class="vt-history">
      <div class="pg-head">
        <div>
          <h1 class="pg-title">Parameter history</h1>
          <span class="pg-count micro-label" data-hist-meta></span>
        </div>
      </div>
      <p class="vt-note micro-label">
        How each protocol parameter has moved over time, one row per parameter. A vote can
        shift a parameter by at most one step per epoch and only within its allowable range,
        so most rows are slow ramps — open “details” for the per-epoch steps.
      </p>
      <div data-history></div>
    </div>`;
  el.querySelector('[data-save]').addEventListener('click', save);
  el.querySelector('[data-clear]').addEventListener('click', () => {
    for (const input of root.querySelectorAll('.vt-input')) input.value = '';
    setStatus('Cleared inputs — press “Save votes” to apply.', 'muted');
  });
  // Preflight gate: disable Save while no api_key is set (instead of only
  // erroring on click). The server stays authoritative on key validity.
  const saveBtn = el.querySelector('[data-save]');
  if (votingAuthUnsub) votingAuthUnsub();
  votingAuthUnsub = subscribe((s) => {
    const noKey = s === 'none';
    saveBtn.disabled = noKey;
    saveBtn.title = noKey ? 'Set your api_key via the Authorize chip to set votes' : '';
  });
  historyLoaded = false;
  historyLoading = false;
  historyAttempts = 0;
  loadHistory();
}

// Boundaries change at most once per voting epoch (~34h on mainnet), so the
// change history is fetched once per visit. `historyLoading` collapses the
// mount()+first-poll race into a single in-flight request; after
// HISTORY_MAX_ATTEMPTS transient/absent results we stop (a node without the
// endpoint shouldn't be polled every 4s forever).
let historyLoaded = false;
let historyLoading = false;
let historyAttempts = 0;
const HISTORY_MAX_ATTEMPTS = 3;

function historyNote(text) {
  return Object.assign(document.createElement('p'), {
    className: 'vt-note micro-label',
    textContent: text,
  });
}

async function loadHistory() {
  const host = root && root.querySelector('[data-history]');
  if (!host || historyLoaded || historyLoading) return;
  historyLoading = true;
  try {
    await loadHistoryInner(host);
  } finally {
    historyLoading = false;
  }
}

async function loadHistoryInner(host) {
  const h = await api.votesHistory();
  if (!h) {
    historyAttempts += 1;
    // getJson() collapses a 404 (endpoint not mounted) and a transient blip to
    // the same null. Retry a few times for the transient case, then give up so
    // a node that structurally lacks the endpoint isn't polled forever.
    if (historyAttempts >= HISTORY_MAX_ATTEMPTS) {
      historyLoaded = true;
      host.replaceChildren(historyNote('Change history is unavailable on this node.'));
    }
    return;
  }
  historyLoaded = true;
  const meta = root.querySelector('[data-hist-meta]');
  if (meta) meta.textContent = h.epochLength ? `epoch ${num(h.epochLength)} blocks` : '';
  const changes = h.changes || [];
  if (changes.length === 0) {
    host.replaceChildren(
      Object.assign(document.createElement('p'), {
        className: 'vt-note micro-label',
        textContent: 'No protocol-parameter changes recorded yet.',
      }),
    );
    return;
  }
  // Regroup the per-boundary events into one trajectory per parameter (the
  // events are ascending by height, so each parameter's steps stay in order).
  const byId = new Map();
  for (const ev of changes) {
    for (const c of ev.params || []) {
      let g = byId.get(c.id);
      if (!g) {
        g = { id: c.id, name: c.name, description: c.description, steps: [] };
        byId.set(c.id, g);
      }
      g.steps.push({ height: ev.height, from: c.from, to: c.to });
    }
  }
  const groups = [...byId.values()].sort((a, b) => a.id - b.id);
  host.replaceChildren(...groups.map(renderParamGroup));
}

// One parameter's trajectory: net from→to, a sparkline of value-over-time, the
// step count + height span, and an expandable per-epoch step list.
function renderParamGroup(g) {
  const first = g.steps[0];
  const last = g.steps[g.steps.length - 1];
  const baseline = first.from; // null when the parameter activated here
  const hasBaseline = baseline !== null && baseline !== undefined;

  const wrap = document.createElement('div');
  wrap.className = 'vt-hist-group';

  const row = document.createElement('div');
  row.className = 'vt-hist-row';

  const name = document.createElement('div');
  name.className = 'vt-hist-pname';
  name.textContent = g.name;
  // Parity with the voting table: surface the parameter explanation on hover
  // (blockVersion has no votable description — it only appears in history).
  if (g.description) name.title = g.description;

  const net = document.createElement('div');
  net.className = 'vt-hist-net';
  const arrow = !hasBaseline ? '•' : last.to > baseline ? '↑' : last.to < baseline ? '↓' : '→';
  net.textContent = `${hasBaseline ? num(baseline) : '—'} → ${num(last.to)} ${arrow}`;

  const spark = document.createElement('div');
  spark.className = 'vt-hist-spark';
  // Series = baseline (if numeric) then each post-step value. Needs ≥2 points.
  const series = (hasBaseline ? [baseline] : []).concat(g.steps.map((s) => s.to));
  if (series.length > 1) spark.append(sparkline(series, { color: 'var(--blue)', w: 120, h: 18 }));

  const count = document.createElement('div');
  count.className = 'vt-hist-count';
  const span =
    first.height === last.height
      ? `h${num(first.height)}`
      : `h${num(first.height)}→${num(last.height)}`;
  count.textContent = `${g.steps.length} step${g.steps.length === 1 ? '' : 's'} · ${span}`;

  const toggle = document.createElement('button');
  toggle.type = 'button';
  toggle.className = 'vt-hist-toggle';
  toggle.textContent = 'details';

  row.append(name, net, spark, count, toggle);
  wrap.append(row);

  const steps = document.createElement('ul');
  steps.className = 'vt-hist-steps';
  steps.hidden = true;
  for (const s of g.steps.slice().reverse()) {
    // newest step first
    const li = document.createElement('li');
    const at = document.createElement('span');
    at.className = 'vt-hist-at';
    at.textContent = `h${num(s.height)}`;
    const delta = document.createElement('span');
    delta.className = 'vt-hist-delta';
    const from = s.from === null || s.from === undefined ? '—' : num(s.from);
    delta.textContent = `${from} → ${num(s.to)}`;
    li.append(at, delta);
    steps.append(li);
  }
  toggle.addEventListener('click', () => {
    steps.hidden = !steps.hidden;
    toggle.textContent = steps.hidden ? 'details' : 'hide';
  });
  wrap.append(steps);
  return wrap;
}

async function load() {
  const v = await api.votes();
  if (!v) {
    setStatus('Could not load voting data.', 'err');
    loadFailed = true;
    return;
  }
  // Clear the transient load-error once data loads again — but never clobber a
  // save result (Saved / Rejected), which is not a load failure.
  if (loadFailed) {
    setStatus('', 'muted');
    loadFailed = false;
  }
  const meta = root.querySelector('[data-meta]');
  if (meta) {
    meta.textContent = `block ${num(v.blockHeight)} · v${v.blockVersion} · epoch start ${num(v.epochStartHeight)}`;
  }
  const params = v.votableParameters || [];
  const configured = v.configuredVotes || [];
  // Rebuild when the rendered id set (votable ∪ configured) changes; otherwise
  // a light cell refresh that leaves the operator's in-progress edits intact.
  if (rowsKey(params, configured) !== builtKey) buildRows(params, configured);
  else refreshCells(params, configured);
  // Retry the one-shot history fetch until it lands (first paint, or after a
  // transient failure); a new boundary mid-session is rare enough to ignore.
  if (!historyLoaded) loadHistory();
}

export async function onSlow() {
  await load();
}
