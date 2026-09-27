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
import { getApiKey, subscribe, authState, CONFIGURE_API_KEY } from './auth.js';


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
let latestVotes = null;
let epochLength = null;
const displayName = (name) => ({ storageFeeFactor: 'Storage rent', minValuePerByte: 'Minimum value per byte', maxBlockSize: 'Maximum block size', maxBlockCost: 'Maximum block cost', tokenAccessCost: 'Token access cost', inputCost: 'Input cost', dataInputCost: 'Data input cost', outputCost: 'Output cost', blockVersion: 'Block version' })[name] || name;

function refreshSummary() {
  if (!root || !latestVotes) return;
  const v = latestVotes;
  root.querySelector('[data-epoch-start]').textContent = num(v.epochStartHeight);
  root.querySelector('[data-saved-count]').textContent = num((v.configuredVotes || []).length);
  root.querySelector('[data-param-count]').textContent = `${num((v.votableParameters || []).length)} available parameters`;
  const elapsed = epochLength ? Math.max(0, Math.min(epochLength, v.blockHeight - v.epochStartHeight)) : null;
  root.querySelector('[data-epoch-progress]').textContent = elapsed == null ? 'Loading epoch length…' : `${num(elapsed)} / ${num(epochLength)} blocks`;
  root.querySelector('[data-epoch-fill]').style.width = `${elapsed == null ? 0 : elapsed / epochLength * 100}%`;
  root.querySelector('[data-epoch-next]').textContent = epochLength ? `Next boundary at ${num(v.epochStartHeight + epochLength)}` : 'Epoch boundary unavailable';
  root.querySelector('[data-threshold]').textContent = epochLength ? `${num(Math.floor(epochLength / 2) + 1)} blocks` : 'More than half';
  refreshDraft();
}

function refreshDraft() {
  if (!root) return;
  const saved = new Map((latestVotes?.configuredVotes || []).map(v => [v.parameterId, String(v.target)]));
  let changes = 0;
  for (const input of root.querySelectorAll('.vt-input')) {
    const changed = input.value.trim() !== (saved.get(Number(input.dataset.id)) ?? '');
    input.closest('tr').classList.toggle('vt-row--edited', changed);
    if (changed) changes++;
    const parameter = latestVotes?.votableParameters?.find(p => p.id === Number(input.dataset.id));
    const preview = input.closest('tr').querySelector('.vt-vote-preview');
    if (preview) {
      const result = desiredPolicy(parameter, input.value.trim());
      preview.textContent = input.validity.badInput ? 'Enter a whole number or clear the field for no vote.' : result.text;
      preview.dataset.tone = input.validity.badInput ? 'warn' : result.tone;
    }
    for (const button of input.closest('tr').querySelectorAll('[data-vote-step]')) {
      const next = parameter ? parameter.current + Number(button.dataset.voteStep) * parameter.step : null;
      button.disabled = next == null || next < parameter.min || next > parameter.max;
    }
  }
  root.querySelector('[data-draft]').textContent = changes ? `${changes} unsaved change${changes === 1 ? '' : 's'}` : 'Draft matches saved targets';
  root.querySelector('[data-reset]').disabled = !changes;
}

export function onFast({ status }) {
  if (!root || !status) return;
  root.querySelector('[data-chain-context]').textContent = status.sync_state === 'at_tip'
    ? 'Parameters from your local chain tip.'
    : 'Your node is catching up or disconnected. These parameters and epoch reflect its local chain, not necessarily the current network.';
}

// Predict only the next approved change from the live parameter descriptor.
function desiredPolicy(p, raw) {
  if (raw === '') return { tone: 'neutral', text: 'No vote requested. Saving a blank value removes this target.' };
  const target = Number(raw);
  if (!Number.isSafeInteger(target)) return { tone: 'warn', text: 'Enter a whole number.' };
  if (!p) return { tone: 'neutral', text: 'This parameter is not currently votable. Its target is retained until changed or cleared.' };
  if (target < p.min || target > p.max) return { tone: 'warn', text: `Choose a value from ${num(p.min)} to ${num(p.max)}.` };
  if (target === p.current) return { tone: 'neutral', text: 'Desired value reached: no vote while the current value equals this target. Voting resumes if it moves away.' };
  const next = p.current + (target > p.current ? p.step : -p.step);
  let text = `Vote to ${target > p.current ? 'increase' : 'decrease'}. Next network-approved value: ${num(next)}. Mining and network approval are required.`;
  let tone = 'direction';
  if ([1, 2, 9].includes(p.id)) {
    if (Math.abs(target - p.current) % p.step !== 0) {
      text += ' This target falls between steps; the node may alternate increase and decrease votes around it.';
      tone = 'warn';
    }
  } else {
    text += ' Step size changes with the parameter; an exact target may be skipped, causing votes to reverse around it.';
  }
  return { tone, text };
}

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
    const hasConfiguredVote = cfg.has(r.id);
    const tr = document.createElement('tr');
    tr.dataset.id = String(r.id);
    tr.classList.toggle('vt-row--active', hasConfiguredVote);
    const nameTd = document.createElement('td');
    nameTd.dataset.label = 'Parameter';
    const nameLine = document.createElement('div');
    nameLine.className = 'vt-name';
    nameLine.textContent = displayName(r.name);
    if (!r.votable) {
      // Configured but not in the current votable set — keep it, but flag it.
      const hint = document.createElement('span');
      hint.className = 'vt-inactive';
      hint.textContent = ' (not active)';
      nameLine.append(hint);
    }
    nameTd.append(nameLine);
    const codeName = document.createElement('code');
    codeName.className = 'vt-code';
    codeName.textContent = r.name;
    nameTd.append(codeName);
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
    live.dataset.label = 'Saved target';
    paintLiveCell(live, hasConfiguredVote, cfg.get(r.id));
    tr.append(live);
    // editable target input
    const inputTd = document.createElement('td');
    inputTd.dataset.label = 'Desired value';
    const input = document.createElement('input');
    input.type = 'number';
    input.className = 'input vt-input';
    if (r.votable) {
      input.min = String(r.min);
      input.max = String(r.max);
      input.step = '1'; // Integer goal, not a multiple of today's step.
    }
    input.placeholder = 'no vote';
    input.setAttribute('aria-label', `${displayName(r.name)} desired value`);
    input.setAttribute('aria-describedby', `vt-policy-${r.id}`);
    input.dataset.id = String(r.id);
    input.dataset.name = r.name;
    input.addEventListener('input', refreshDraft);
    input.classList.toggle('vt-input--active', hasConfiguredVote);
    if (hasConfiguredVote) input.value = String(cfg.get(r.id));
    inputTd.append(input);
    tr.append(inputTd);
    const controls = document.createElement('td');
    controls.className = 'vt-target-tools';
    controls.colSpan = 6;
    const buttons = document.createElement('div');
    buttons.className = 'vt-step-buttons';
    for (const [direction, label] of [[-1, '− One step'], [1, '+ One step'], [0, 'No vote']]) {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'btn btn--ghost';
      button.textContent = label;
      button.setAttribute('aria-label', direction === 0 ? `Clear ${displayName(r.name)} desired value` : `${direction > 0 ? 'Increase' : 'Decrease'} ${displayName(r.name)} by one step from current`);
      if (direction) button.dataset.voteStep = String(direction);
      button.addEventListener('click', () => {
        const p = latestVotes?.votableParameters?.find(p => p.id === r.id);
        if (!direction) input.value = '';
        else if (p) {
          const next = p.current + direction * p.step;
          if (next < p.min || next > p.max) return;
          input.value = String(next);
        }
        refreshDraft();
      });
      buttons.append(button);
    }
    const preview = document.createElement('p');
    preview.id = `vt-policy-${r.id}`;
    preview.className = 'vt-vote-preview';
    controls.append(buttons, preview);
    tr.append(controls);
    tbody.append(tr);
  }
  builtKey = rowsKey(params, configured);
}

function paintLiveCell(cellEl, active, value) {
  cellEl.textContent = active ? num(value) : '—';
  cellEl.classList.toggle('vt-live--active', active);
}

// Light per-poll refresh: update the read-only current + live-target cells
// without touching the operator's in-progress input edits.
function refreshCells(params, configured) {
  const cfg = new Map(configured.map((c) => [c.parameterId, c.target]));
  const curById = new Map(params.map((p) => [p.id, p.current]));
  for (const tr of root.querySelectorAll('tr[data-id]')) {
    const id = Number(tr.dataset.id);
    const hasConfiguredVote = cfg.has(id);
    tr.classList.toggle('vt-row--active', hasConfiguredVote);
    const cur = tr.querySelector('.vt-current');
    if (cur && curById.has(id)) cur.textContent = num(curById.get(id));
    const live = tr.querySelector('.vt-live');
    if (live) paintLiveCell(live, hasConfiguredVote, cfg.get(id));
    const input = tr.querySelector('.vt-input');
    if (input) input.classList.toggle('vt-input--active', hasConfiguredVote);
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
    if (input.validity.badInput) { invalid.push(`${input.dataset.name} must be a whole number`); continue; }
    const raw = input.value.trim();
    if (raw === '') continue;
    const label = input.dataset.name || `id ${input.dataset.id}`;
    const target = Number(raw);
    if (!Number.isFinite(target)) {
      invalid.push(`${label} is not a number`);
      continue;
    }
    if (!Number.isInteger(target)) {
      invalid.push(`${label} must be a whole number`);
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
    setStatus(authState() === 'unconfigured' ? CONFIGURE_API_KEY : 'Rejected (403): missing or invalid api_key — use the Authorize chip.', 'err');
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
        <p class="pg-description">Understand the rules. Shape what comes next.</p>
        <span class="pg-count micro-label" data-meta></span>
      </div>
    </div>
    <div class="vt-overview">
      <section class="vt-epoch" aria-label="Local voting epoch">
        <div class="ov-eyebrow">LOCAL VOTING EPOCH</div>
        <h2>Change takes consensus.</h2>
        <p data-chain-context>Loading your local chain context…</p>
        <div class="vt-epoch__numbers"><span>Epoch starts at <b data-epoch-start>—</b></span><strong data-epoch-progress>Loading…</strong></div>
        <div class="gauge"><div class="gauge__fill" data-epoch-fill></div></div>
        <span class="vt-epoch__next" data-epoch-next></span>
      </section>
      <section class="vt-saved" aria-label="Configured voting targets"><span>Saved targets</span><strong data-saved-count>—</strong><p>Targets configured on this node.<br>These are not network vote totals.</p><span class="pill" data-access>Read-only access</span></section>
    </div>
    <details class="vt-guide"><summary>How protocol voting works</summary>
    <div class="vt-rules" aria-label="Voting rules">
      <div class="vt-rule">
        <span class="micro-label">Targets</span>
        <b>Within range</b>
        <span>Blank clears a vote; saves replace the full target set.</span>
      </div>
      <div class="vt-rule">
        <span class="micro-label">Authority</span>
        <b>Authorized mining node</b>
        <span>Viewing is public; writes require an authorized mining node.</span>
      </div>
      <div class="vt-rule">
        <span class="micro-label">Per block</span>
        <b>Two votes</b>
        <span>Extra targets wait while lower numbered parameters settle.</span>
      </div>
      <div class="vt-rule">
        <span class="micro-label">Per epoch</span>
        <b data-threshold>More than half</b>
        <span>Blocks must carry the vote for approval. A parameter moves one step per epoch.</span>
      </div>
    </div></details>
    <div class="vt-section-head"><div><h2>Protocol parameters</h2><p data-param-count>Loading parameters…</p></div><span>Desired value = your long-term goal</span></div>
    <p class="vt-target-help">Set the value you want the protocol to reach. Your miner votes toward it; the network decides each change. One-step buttons choose a value relative to the current parameter. You can also enter a goal manually. Nothing changes until you save.</p>
    <table class="table vt-parameters" aria-label="Protocol voting parameters">
      <thead><tr>
        <th>Parameter</th><th class="table__num">Current</th><th class="table__num">Range</th>
        <th class="table__num">Step</th><th class="table__num">Saved target</th><th>Desired value</th>
      </tr></thead>
      <tbody data-rows></tbody>
    </table>
    <div class="vt-actions">
      <div class="vt-draft"><strong data-draft>Loading targets…</strong><span>Saving replaces the entire target set.</span></div>
      <button class="btn btn--primary" data-save type="button">Save votes</button>
      <button class="btn btn--ghost" data-reset type="button" disabled>Reset draft</button>
      <button class="btn btn--ghost" data-clear type="button">Clear draft</button>
      <span class="vt-status" data-status aria-live="polite"></span>
      <p class="vt-access-note" data-access-note>Authorize using the sidebar to save targets. You can explore and prepare a draft here.</p>
    </div>
    <div class="vt-history">
      <div class="pg-head">
        <div>
          <h2 class="pg-title">Parameter history</h2>
          <span class="pg-count micro-label" data-hist-meta></span>
        </div>
      </div>
      <p class="vt-note micro-label">
        Select a parameter to explore its recorded changes on your local chain. A vote can
        shift a parameter by at most one step per epoch and only within its allowable range,
        with exact transitions available in the change ledger below.
      </p>
      <div data-history></div>
    </div>`;
  el.querySelector('[data-save]').addEventListener('click', save);
  el.querySelector('[data-reset]').addEventListener('click', () => {
    const saved = new Map((latestVotes?.configuredVotes || []).map(v => [v.parameterId, v.target]));
    for (const input of root.querySelectorAll('.vt-input')) input.value = saved.get(Number(input.dataset.id)) ?? '';
    refreshDraft();
    setStatus('Draft restored to the latest saved targets.', 'muted');
  });
  el.querySelector('[data-clear]').addEventListener('click', () => {
    for (const input of root.querySelectorAll('.vt-input')) input.value = '';
    setStatus('Cleared inputs — press “Save votes” to apply.', 'muted');
    refreshDraft();
  });
  // Preflight gate: disable Save while no api_key is set (instead of only
  // erroring on click). The server stays authoritative on key validity.
  const saveBtn = el.querySelector('[data-save]');
  if (votingAuthUnsub) votingAuthUnsub();
  votingAuthUnsub = subscribe((s) => {
    const noKey = s === 'none' || s === 'unconfigured';
    saveBtn.disabled = noKey;
    saveBtn.title = s === 'unconfigured' ? CONFIGURE_API_KEY : noKey ? 'Set your api_key via the Authorize chip to set votes' : '';
    root.querySelector('[data-access]').textContent = noKey ? 'Read-only access' : 'Operator key set';
    root.querySelector('[data-access-note]').textContent = s === 'unconfigured' ? CONFIGURE_API_KEY : noKey ? 'Authorize using the sidebar to save targets. You can explore and prepare a draft here.' : 'Saving requires a valid operator key and mining enabled on this node.';
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
  epochLength = h.epochLength || null;
  refreshSummary();
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
  renderHistoryExplorer(host, groups);
}

// History uses block-height spacing and step interpolation: a parameter stays
// constant between recorded changes. The slider offers the same exact readout
// by keyboard or touch; the ledger exposes every recorded transition.
function historyEl(tag, cls, text) {
  const el = document.createElement(tag);
  if (cls) el.className = cls;
  if (text != null) el.textContent = text;
  return el;
}

function renderHistoryExplorer(host, groups) {
  const shell = historyEl('section', 'vh-explorer');
  const tools = historyEl('div', 'vh-toolbar');
  const label = historyEl('label', '', 'Parameter');
  const select = historyEl('select', 'select');
  for (const g of groups) {
    const option = historyEl('option', '', displayName(g.name));
    option.value = String(g.id);
    select.append(option);
  }
  label.append(select);
  tools.append(label, historyEl('span', 'vh-scope', 'Recorded changes on your local chain'));
  const content = historyEl('div', 'vh-content');
  shell.append(tools, content);
  host.replaceChildren(shell);
  const render = () => {
    const g = groups.find(g => String(g.id) === select.value);
    if (!g) return;
    content.replaceChildren();
    const steps = g.steps.slice().sort((a,b) => a.height - b.height);
    const first = steps[0], last = steps.at(-1);
    const unit = g.name === 'maxBlockSize' ? 'bytes' : g.name === 'blockVersion' ? 'version' : g.name === 'maxBlockCost' ? 'cost units' : 'parameter units';
    const stats = historyEl('div', 'vh-stats');
    for (const [title, value, note] of [
      ['Latest recorded value', num(last.to), unit],
      ['Before first change', first.from == null ? 'Not active' : num(first.from), `at block ${num(first.height)}`],
      ['Recorded changes', num(steps.length), `latest at block ${num(last.height)}`],
    ]) {
      const item = historyEl('div');
      item.append(historyEl('span','',title),historyEl('strong','',value),historyEl('small','',note));
      stats.append(item);
    }
    content.append(stats);
    if (g.description) content.append(historyEl('p','vh-description',g.description));
    if (steps.length > 1) content.append(historyPlot(g, steps, unit));
    else content.append(historyEl('p','vh-single',`One recorded transition at block ${num(first.height)}: ${first.from == null ? 'not active' : num(first.from)} → ${num(first.to)}. There is no multi-epoch trend to plot.`));
    const ledger = historyEl('details','vh-ledger');
    ledger.append(historyEl('summary','',`Inspect all ${num(steps.length)} changes`));
    const scroll = historyEl('div','vh-ledger-scroll');
    const table = historyEl('table');
    table.setAttribute('aria-label', `${displayName(g.name)} recorded changes`);
    const head = document.createElement('thead');
    const row = document.createElement('tr');
    for (const text of ['Block height','Previous','New value','Change']) row.append(historyEl('th','',text));
    head.append(row); table.append(head);
    const body = document.createElement('tbody');
    for (const s of steps.slice().reverse()) {
      const row = document.createElement('tr');
      const delta = s.from == null ? 'Activated' : `${s.to - s.from > 0 ? '+' : ''}${num(s.to - s.from)}`;
      for (const text of [num(s.height),s.from == null ? '—' : num(s.from),num(s.to),delta]) row.append(historyEl('td','',text));
      body.append(row);
    }
    table.append(body); scroll.append(table); ledger.append(scroll); content.append(ledger);
  };
  select.addEventListener('change', render);
  render();
}

function historyPlot(g, steps, unit) {
  const NS = 'http://www.w3.org/2000/svg';
  const svgEl = (tag, attrs) => {
    const el = document.createElementNS(NS,tag);
    for (const [key,value] of Object.entries(attrs)) el.setAttribute(key,String(value));
    return el;
  };
  const wrap = historyEl('div','vh-chart');
  const heading = historyEl('div','vh-chart-heading');
  heading.append(historyEl('span','',`Recorded value · ${unit}`),historyEl('span','','Block height →'));
  const plot = historyEl('div','vh-plot');
  const axis = historyEl('div','vh-yaxis');
  const first = steps[0], last = steps.at(-1);
  const values = steps.map(s=>s.to).concat(first.from == null ? [] : [first.from]);
  const low = Math.min(...values), high = Math.max(...values);
  const range = high - low || Math.max(1,Math.abs(high)*.01);
  const min = low - range*.08, max = high + range*.08;
  const x = h => (h-first.height)/Math.max(1,last.height-first.height)*800;
  const y = v => 220-(v-min)/(max-min)*220;
  const svg = svgEl('svg',{viewBox:'0 0 800 220',preserveAspectRatio:'none',role:'img','aria-label':`${displayName(g.name)} step chart from block ${num(first.height)} to ${num(last.height)}. Exact changes are available in the inspector and ledger.`});
  for (const value of [high,(high+low)/2,low]) {
    const tick = historyEl('span','',num(Math.round(value)));
    tick.style.top=`${y(value)/220*100}%`;
    axis.append(tick);
    svg.append(svgEl('line',{x1:0,x2:800,y1:y(value),y2:y(value),class:'vh-grid'}));
  }
  let d=`M0 ${y(first.from ?? first.to)}`;
  for (const s of steps) d+=` H${x(s.height)} V${y(s.to)}`;
  svg.append(svgEl('path',{d:`${d} L800 220 L0 220 Z`,class:'vh-area'}));
  svg.append(svgEl('path',{d,class:'vh-line'}));
  const cross=svgEl('line',{x1:800,x2:800,y1:0,y2:220,class:'vh-cross'});
  const dot=svgEl('circle',{cx:800,cy:y(last.to),r:4,class:'vh-dot'});
  svg.append(cross,dot); plot.append(axis,svg);
  const xaxis=historyEl('div','vh-xaxis');
  for (const h of [first.height,Math.round((first.height+last.height)/2),last.height]) xaxis.append(historyEl('span','',num(h)));
  const label=historyEl('label','vh-inspector-label','Inspect a recorded change');
  const slider=historyEl('input','vh-slider'); slider.type='range';slider.min='0';slider.max=String(steps.length-1);slider.step='1';slider.value=slider.max;
  label.append(slider);
  const readout=historyEl('output','vh-readout');
  function inspect(index) {
    const s=steps[index];
    const delta=s.from == null ? 'Activated' : `${s.to-s.from>0?'+':''}${num(s.to-s.from)} ${unit}`;
    readout.textContent=`Block ${num(s.height)} · ${s.from == null ? 'not active' : num(s.from)} → ${num(s.to)} · ${delta}`;
    slider.setAttribute('aria-valuetext',readout.textContent);
    cross.setAttribute('x1',x(s.height));cross.setAttribute('x2',x(s.height));dot.setAttribute('cx',x(s.height));dot.setAttribute('cy',y(s.to));
  }
  slider.addEventListener('input',()=>inspect(Number(slider.value)));
  svg.addEventListener('pointermove',event=>{
    const rect=svg.getBoundingClientRect();
    const height=first.height+Math.max(0,Math.min(1,(event.clientX-rect.left)/rect.width))*(last.height-first.height);
    let nearest=0;
    for(let i=1;i<steps.length;i++) if(Math.abs(steps[i].height-height)<Math.abs(steps[nearest].height-height)) nearest=i;
    slider.value=String(nearest);inspect(nearest);
  });
  inspect(steps.length-1);
  wrap.append(heading,plot,xaxis,label,readout,historyEl('p','vh-chart-note','Horizontal distance represents block height. Values stay constant between recorded changes; the vertical scale is fitted to this parameter. Drag the slider or use arrow keys to inspect exact transitions.'));
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
  const previousSaved = new Map((latestVotes?.configuredVotes || []).map(c => [c.parameterId, String(c.target)]));
  const drafts = new Map();
  for (const input of root.querySelectorAll('.vt-input')) {
    if (input.value.trim() !== (previousSaved.get(Number(input.dataset.id)) ?? '')) drafts.set(input.dataset.id, input.value);
  }
  latestVotes = v;
  const configured = v.configuredVotes || [];
  // Rebuild when the rendered id set (votable ∪ configured) changes; otherwise
  // a light cell refresh that leaves the operator's in-progress edits intact.
  if (rowsKey(params, configured) !== builtKey) {
    buildRows(params, configured);
  }
  else refreshCells(params, configured);
  const currentSaved = new Map(configured.map(c => [c.parameterId, String(c.target)]));
  for (const input of root.querySelectorAll('.vt-input')) {
    input.value = drafts.has(input.dataset.id) ? drafts.get(input.dataset.id) : currentSaved.get(Number(input.dataset.id)) ?? '';
  }
  refreshSummary();
  // Retry the one-shot history fetch until it lands (first paint, or after a
  // transient failure); a new boundary mid-session is rare enough to ignore.
  if (!historyLoaded) loadHistory();
}

export async function onSlow() {
  await load();
}
