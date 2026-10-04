import { api } from './api-client.js';
import { decimal } from './wallet-transaction.js';

const terminal = new Set(['mined', 'cancelled', 'expired', 'failed']);
// Conflicted private transactions can become eligible again after a rollback.
export function canCancelMaintenance(state) { return !terminal.has(state); }
const kinds = { consolidate: 'Consolidate selected boxes', renew: 'Renew selected boxes', rewards: 'Retrieve selected mining rewards' };
const jobKinds = { ...kinds, send: 'Fixed payment' };
function el(tag, text, className) { const n = document.createElement(tag); if (text != null) n.textContent = text; if (className) n.className = className; return n; }
function field(title, control) { const label = el('label', null, 'w-field'); label.append(el('span', title, 'w-label'), control); return label; }

export function eligibleFor(task, box) {
  if (task === 'rewards') return box.provenance?.type === 'minerReward' && ['confirmed', 'immature'].includes(box.status?.type);
  return box.provenance?.type === 'owned' && box.status?.type === 'confirmed';
}
// Immature rewards cannot be spent before maturity; a job waits until then
// without spending attempts, so its start height may not be earlier.
export function earliestStart(boxes) {
  return Math.max(0, ...boxes.map(box => box.status?.type === 'immature' ? box.status.maturesAtHeight : 0));
}
export function makeMaintenanceRequest(task, boxes, destination, start, expiry, attempts, label) {
  if (!Object.hasOwn(kinds, task) || !boxes.length || boxes.length > 100 || boxes.some(box => !eligibleFor(task, box))) throw Error('Select 1–100 eligible boxes.');
  const boxIds = boxes.map(box => box.boxId);
  if (new Set(boxIds).size !== boxIds.length || boxIds.some(id => !/^[a-f0-9]{64}$/.test(id))) throw Error('Selected box identifiers are invalid.');
  for (const value of [start, expiry, attempts]) if (!/^\d+$/.test(String(value)) || !Number.isSafeInteger(Number(value))) throw Error('Enter whole block heights and attempts.');
  if (Number(start) > 4294967295 || Number(expiry) > 4294967295 || Number(expiry) <= Number(start) || Number(attempts) < 1 || Number(attempts) > 100) throw Error('Use a later expiry height and 1–100 attempts.');
  if (Number(start) < earliestStart(boxes)) throw Error(`Selected rewards mature at height ${earliestStart(boxes)}; start at or after it.`);
  if (!label.trim() || new TextEncoder().encode(label).length > 160) throw Error('Enter a label of at most 160 bytes.');
  if (task !== 'renew' && !destination) throw Error('Choose a receiving address from this wallet.');
  return { label, task: { type: task, boxIds, ...(task === 'renew' ? {} : { destination }) }, notBeforeHeight: Number(start), expiresAtHeight: Number(expiry), maxAttempts: Number(attempts) };
}
// What an approved job signs when due, so the owner can review it before and
// after unlocking. Consolidation and reward retrieval send every selected unit.
export function describeMaintenanceJob(job) {
  const { task, notBeforeHeight, expiresAtHeight } = job.request;
  const inputs = task.type === 'send' ? task.intent?.inputs?.boxIds : task.boxIds;
  const recipients = task.type === 'send'
    ? (task.intent?.outputs || []).map(output => ({ address: output.address, nanoErg: output.value, assets: output.assets || [] }))
    : task.type === 'renew' ? [] : [{ address: task.destination, nanoErg: null, assets: [] }];
  return { kind: jobKinds[task.type] || task.type, payment: task.type === 'send', inputs: inputs?.length || 0, recipients, start: notBeforeHeight, expiry: expiresAtHeight };
}
export function recipientLines(description) {
  if (!description.recipients.length) return ['Each box returns to its current wallet recipient.'];
  return description.recipients.map(({ address, nanoErg, assets }) => nanoErg == null
    ? `All selected ERG and tokens go to ${address}.`
    : `Pays ${decimal(nanoErg)} ERG${assets.length ? ' and ' + assets.map(asset => `${asset.amount} units of ${asset.tokenId}`).join(', ') : ''} to ${address}.`);
}
// Jobs that can still sign or submit. Conflicted work waits on a rollback.
export function pendingMaintenance(jobs) {
  const pending = (jobs || []).filter(job => !terminal.has(job.state) && job.state !== 'conflicted');
  return { pending, payments: pending.filter(job => job.request.task.type === 'send') };
}
export function summarizeBoxes(boxes) {
  const tokens = new Map(); let nanoErg = 0n;
  for (const box of boxes) { nanoErg += BigInt(box.value); for (const asset of box.assets || []) tokens.set(asset.tokenId, (tokens.get(asset.tokenId) || 0n) + BigInt(asset.amount)); }
  return { nanoErg: String(nanoErg), tokens: [...tokens].map(([tokenId, amount]) => ({ tokenId, amount: String(amount) })) };
}

export function createWalletMaintenance(root, { onJobs } = {}) {
  let disposed = false, busy = false, epoch = 0, offset = 0, selected = new Map(), currentBoxes = [], request = null, status = null, unlocked = false;
  const intro = el('p', 'Approve one finite operation for a block mined by this node. Selected inputs stay reserved; the node signs while unlocked once the start height is reached. Miner fee: 0 ERG.');
  const lockedNote = el('p', 'Unlock the wallet to approve operations. Pending operations below sign automatically when due after you unlock; cancel any you do not recognize.', 'wb-note');
  const form = el('form', null, 'w-form'), kind = el('select'), destination = el('select'), label = el('input'), start = el('input'), expiry = el('input'), attempts = el('input');
  for (const [value, title] of Object.entries(kinds)) { const option = el('option', title); option.value = value; kind.append(option); }
  label.value = 'Wallet maintenance'; start.type = expiry.type = attempts.type = 'number'; start.min = '0'; expiry.min = '1'; attempts.min = '1'; attempts.max = '100'; attempts.value = '10';
  form.append(field('Operation', kind), field('Label', label), field('Receiving address', destination), field('Start at block height', start), field('Expire after block height', expiry), field('Maximum attempts', attempts));
  for (const input of [kind, destination, label, start, expiry, attempts]) input.className = 'input';
  const boxes = el('div'), controls = el('div', null, 'wb-actions'), prev = el('button', 'Previous', 'btn btn--sm'), next = el('button', 'Next', 'btn btn--sm'), pageInfo = el('span'), review = el('button', 'Review selected operation', 'btn btn--primary');
  prev.type = next.type = 'button'; review.type = 'submit'; controls.append(prev, pageInfo, next, review); form.append(boxes, controls);
  const note = el('p', '', 'wb-note'), preview = el('div'), history = el('div'); root.replaceChildren(intro, lockedNote, form, note, preview, history);
  function invalidate() { request = null; preview.replaceChildren(); }
  form.addEventListener('input', invalidate);
  function renderBoxes() {
    boxes.replaceChildren(); destination.closest('label').hidden = kind.value === 'renew';
    for (const box of currentBoxes.filter(box => eligibleFor(kind.value, box))) {
      const input = el('input'); input.type = 'checkbox'; input.checked = selected.has(box.boxId); input.disabled = busy;
      input.addEventListener('change', () => {
        if (input.checked) selected.set(box.boxId, box); else selected.delete(box.boxId);
        const maturity = earliestStart([...selected.values()]);
        if (Number(start.value) < maturity) { start.value = String(maturity); if (Number(expiry.value) <= maturity) expiry.value = String(maturity + 720); }
        invalidate();
      });
      const row = el('label', null, 'wb-check'); row.append(input, el('span', `${decimal(box.value)} ERG · ${(box.assets || []).length} tokens · ${box.boxId} · ${box.status.type === 'immature' ? 'matures at ' + box.status.maturesAtHeight : 'confirmed'}`)); boxes.append(row);
    }
    if (!boxes.children.length) boxes.append(el('p', 'No eligible boxes on this page.', 'wb-note'));
    pageInfo.textContent = `Boxes ${offset + 1}–${offset + currentBoxes.length}`;
    prev.disabled = busy || offset === 0; next.disabled = busy || currentBoxes.length < 100;
  }
  async function loadBoxes() {
    if (!unlocked) return;
    const token = ++epoch; const [boxPage, addresses] = await Promise.all([api.wallet.boxes(offset, 100), api.wallet.addresses()]);
    if (disposed || token !== epoch || !unlocked) return;
    if (!boxPage.ok) { note.textContent = boxPage.reason || 'Boxes unavailable.'; return; }
    currentBoxes = boxPage.data.items || []; const oldDestination = destination.value;
    destination.replaceChildren(); for (const address of addresses.ok && Array.isArray(addresses.data) ? addresses.data : []) { const option = el('option', address); option.value = address; destination.append(option); }
    if ([...destination.options].some(option => option.value === oldDestination)) destination.value = oldDestination;
    renderBoxes();
  }
  kind.addEventListener('change', () => { selected.clear(); invalidate(); renderBoxes(); });
  prev.addEventListener('click', () => { offset = Math.max(0, offset - 100); loadBoxes(); }); next.addEventListener('click', () => { offset += 100; loadBoxes(); });
  form.addEventListener('submit', event => {
    event.preventDefault(); if (busy) return;
    try {
      request = makeMaintenanceRequest(kind.value, [...selected.values()], destination.value, start.value, expiry.value, attempts.value, label.value);
      const totals = summarizeBoxes([...selected.values()]); preview.replaceChildren(el('p', `${kinds[kind.value]}: ${selected.size} pinned inputs, ${decimal(totals.nanoErg)} ERG, ${totals.tokens.length} token types. Start ${request.notBeforeHeight}; expiry ${request.expiresAtHeight}; maximum ${request.maxAttempts} attempts. No public broadcast.`));
      for (const asset of totals.tokens) preview.append(el('p', `${asset.tokenId}: ${asset.amount} units`, 'wb-note'));
      preview.append(el('p', kind.value === 'renew' ? 'Every output retains its wallet recipient, ERG, tokens and registers with a new creation height.' : `Destination: ${request.task.destination}. Mining reward retrieval still pays any required re-emission obligation.`));
      const approve = el('button', 'Approve private operation', 'btn btn--primary'); approve.type = 'button'; approve.addEventListener('click', async () => {
        if (busy || !request) return; busy = true; approve.disabled = true;
        const approved = structuredClone(request); const result = await api.wallet.createMiningJob(approved);
        busy = false; if (disposed) return;
        note.textContent = result.ok ? `Job ${result.data.id} approved.` : result.reason || 'Operation was rejected.';
        if (result.ok) { selected.clear(); invalidate(); renderBoxes(); await refresh(); } else approve.disabled = false;
      }); preview.append(approve); note.textContent = '';
    } catch (error) { note.textContent = error.message; }
  });
  async function refresh() {
    const token = epoch; const result = await api.wallet.miningJobs(); if (disposed || token !== epoch) return;
    history.replaceChildren(el('h3', 'Approved operations'));
    if (!result.ok) { history.append(el('p', result.reason || 'Jobs unavailable.', 'wb-note')); return; }
    onJobs?.(result.data.items || []);
    for (const job of result.data.items || []) {
      const description = describeMaintenanceJob(job);
      const row = el('div', null, 'wb-review'); row.append(el('strong', `${job.request.label} · ${job.state}`), el('p', `${description.kind} · ${description.inputs} pinned inputs · start ${description.start} · expires at ${description.expiry} · attempts ${job.attempts}/${job.request.maxAttempts}`));
      for (const line of recipientLines(description)) row.append(el('p', line, 'wb-note'));
      if (job.txId) row.append(el('p', `Transaction ${job.txId}`, 'wb-note'));
      if (job.detail) row.append(el('p', job.detail, 'wb-note'));
      if (canCancelMaintenance(job.state)) { const cancel = el('button', 'Cancel operation', 'btn btn--sm'); cancel.type = 'button'; cancel.addEventListener('click', async () => { if (busy) return; busy = true; cancel.disabled = true; const result = await api.wallet.cancelMiningJob(job.id); busy = false; if (disposed) return; note.textContent = result.ok ? 'Operation cancelled.' : result.reason || 'Cancellation failed.'; await refresh(); }); row.append(cancel); }
      history.append(row);
    }
    if (!(result.data.items || []).length) history.append(el('p', 'No approved operations.', 'wb-note'));
  }
  // Returns true when the wallet became unlocked and the box list must load.
  function update(nextStatus) {
    status = nextStatus; const wasUnlocked = unlocked; unlocked = Boolean(status?.isUnlocked);
    form.hidden = !unlocked; lockedNote.hidden = unlocked;
    if (wasUnlocked && !unlocked) { epoch++; selected.clear(); currentBoxes = []; invalidate(); boxes.replaceChildren(); }
    if (!start.value) { start.value = String(status?.walletHeight || 0); expiry.value = String((status?.walletHeight || 0) + 720); }
    return unlocked && !wasUnlocked;
  }
  return { update, load() { return Promise.all([loadBoxes(), refresh()]); }, refresh, isBusy() { return busy; }, dispose() { disposed = true; epoch++; selected.clear(); request = null; root.replaceChildren(); } };
}
