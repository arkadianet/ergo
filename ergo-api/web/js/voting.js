// Voting page: shows the protocol parameters the operator can vote on (with
// current value + allowed range), and — for a mining node with an API key set —
// lets the operator set vote targets. The node nudges each parameter one step
// per block toward its target, at most two parameters per block.
//
// Reads `GET /api/v1/votes` (open). Writes `POST /api/v1/votes` (auth-gated by
// the operator's api_key; rejected 409 when the node is not mining). The write
// REPLACES the full target set.
import { api } from './api-client.js';
import { num } from './format.js';
import { getApiKey } from './settings.js';

let root = null;
// Signature of the rows currently built (see `rowsKey`). The 4s poll only
// rebuilds inputs when this changes; otherwise it refreshes read-only cells so
// the operator's in-progress edits are never clobbered.
let builtKey = null;
// True while the last poll's fetch failed, so a recovered fetch can clear the
// "Could not load voting data." error without clobbering a save result.
let loadFailed = false;

function cell(text, cls) {
  const td = document.createElement('td');
  if (cls) td.className = cls;
  td.textContent = text;
  return td;
}

function setStatus(msg, kind) {
  const el = root.querySelector('[data-status]');
  if (!el) return;
  el.textContent = msg || '';
  el.style.color =
    kind === 'ok' ? 'var(--green)' : kind === 'err' ? 'var(--red)' : 'var(--tx3)';
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
      cell(num(r.current), 'vt-num vt-current'),
      cell(r.votable ? `${num(r.min)} – ${num(r.max)}` : '—', 'vt-num vt-range'),
      cell(num(r.step), 'vt-num'),
    );
    // configured (live) target cell
    const live = document.createElement('td');
    live.className = 'vt-num vt-live';
    live.textContent = cfg.has(r.id) ? num(cfg.get(r.id)) : '—';
    tr.append(live);
    // editable target input
    const inputTd = document.createElement('td');
    const input = document.createElement('input');
    input.type = 'number';
    input.className = 'vt-input';
    if (r.votable) {
      input.min = String(r.min);
      input.max = String(r.max);
      input.step = String(r.step);
    }
    input.placeholder = 'no vote';
    input.dataset.id = String(r.id);
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
    setStatus('Set your API key in ⚙ Settings to change votes.', 'err');
    return;
  }
  // Collect non-blank inputs as the full desired set (replace semantics).
  const votes = [];
  for (const input of root.querySelectorAll('.vt-input')) {
    const raw = input.value.trim();
    if (raw === '') continue;
    const target = Number(raw);
    if (!Number.isFinite(target)) continue;
    votes.push({ parameterId: Number(input.dataset.id), target });
  }
  setStatus('Saving…', 'muted');
  const res = await api.setVotes(votes);
  if (res.ok) {
    setStatus(votes.length ? `Saved ${votes.length} vote target(s).` : 'Cleared all votes.', 'ok');
    await load();
    return;
  }
  if (res.status === 403) {
    setStatus('Rejected (403): missing or invalid API key — check ⚙ Settings.', 'err');
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
    <div class="pg-head"><span class="pg-title">Voting</span>
      <span class="pg-count micro-label" data-meta></span></div>
    <p class="vt-note micro-label">
      Set the value the node should vote toward for each parameter. The node moves each
      one step per block, at most two parameters per block. Setting requires an API key
      (⚙ Settings) and a mining node; viewing is always available.
    </p>
    <table class="vtable">
      <thead><tr>
        <th>Parameter</th><th class="vt-num">Current</th><th class="vt-num">Range</th>
        <th class="vt-num">Step</th><th class="vt-num">Voting</th><th>Target</th>
      </tr></thead>
      <tbody data-rows></tbody>
    </table>
    <div class="vt-actions">
      <button class="btn btn--primary" data-save type="button">Save votes</button>
      <button class="btn" data-clear type="button">Clear all</button>
      <span class="vt-status" data-status></span>
    </div>`;
  el.querySelector('[data-save]').addEventListener('click', save);
  el.querySelector('[data-clear]').addEventListener('click', () => {
    for (const input of root.querySelectorAll('.vt-input')) input.value = '';
    setStatus('Cleared inputs — press “Save votes” to apply.', 'muted');
  });
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
}

export async function onSlow() {
  await load();
}
