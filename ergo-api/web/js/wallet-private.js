// Authenticated queue management. Signed imports never use public submission.
import { decimal } from './wallet-transaction.js';

const node = (tag, text, attrs = {}) => {
  const result = document.createElement(tag);
  if (text !== null) result.textContent = text;
  for (const [key, value] of Object.entries(attrs)) result.setAttribute(key, value);
  return result;
};
const time = value => value ? new Date(value).toLocaleString() : 'No deadline';

export function createPrivateMiningQueue(host, { api, active = () => true }) {
  let disposed = false, busy = false, version = 0;
  const status = node('p', 'Loading private transactions…', { role: 'status', class: 'wb-note' });
  const items = node('div', null, { class: 'wb-recipients' });
  const refresh = node('button', 'Refresh queue', { type: 'button', class: 'btn btn--sm' });
  const bytes = node('textarea', null, { class: 'input', rows: '4', spellcheck: 'false', placeholder: 'Signed transaction bytes · hex', 'aria-label': 'Signed transaction bytes' });
  const label = node('input', null, { class: 'input', maxlength: '200', placeholder: 'Label · optional', 'aria-label': 'Private transaction label' });
  const expiry = node('input', null, { class: 'input', type: 'datetime-local', 'aria-label': 'Private transaction deadline' });
  const expiryHeight = node('input', null, { class: 'input', type: 'number', min: '1', max: '4294967295', step: '1', placeholder: 'Last eligible block height · optional', 'aria-label': 'Last eligible private mining height' });
  const priority = node('input', null, { class: 'input', type: 'number', min: '-2147483648', max: '2147483647', step: '1', value: '0', 'aria-label': 'Private queue priority' });
  const consent = node('input', null, { type: 'checkbox' });
  const consentLabel = node('label', null, { class: 'wb-check' });
  consentLabel.append(consent, node('span', 'I reviewed this signed transaction and want it included only in a block this node mines.'));
  const submit = node('button', 'Import signed transaction privately', { type: 'button', class: 'btn btn--primary' });
  submit.disabled = true;
  consent.addEventListener('change', () => { submit.disabled = busy || !consent.checked; });
  const importForm = node('details', null, { class: 'wb-advanced' });
  importForm.append(node('summary', 'Import from an external signer'),
    node('p', 'A phone or another wallet can sign the transaction. Import its signed bytes here to keep it out of this node’s public mempool. Zero fees require a transaction built without a miner-fee output.', { class: 'wb-note' }),
    bytes, label, node('p', 'Optional expiry · local time', { class: 'wb-note' }), expiry, expiryHeight,
    node('p', 'Queue priority · larger values are selected first', { class: 'wb-note' }), priority, consentLabel, submit);
  host.replaceChildren(node('h3', 'Private mining queue'),
    node('p', 'These transactions wait for your own block. Their inputs stay reserved while waiting. Cancellation and expiry withdraw local mining work; transactions become public when a mined block is published.', { class: 'wb-note' }),
    refresh, status, items, importForm);

  function error(response) {
    return response?.data?.error?.detail || response?.data?.detail || response?.reason || 'Private queue request failed.';
  }
  async function load() {
    const current = ++version;
    const response = await api.privateTransactions();
    if (disposed || !active() || current !== version) return;
    if (!response?.ok) { status.textContent = error(response); items.replaceChildren(); return; }
    const list = response.data?.items;
    if (!Array.isArray(list)) { status.textContent = 'The node returned an invalid queue response.'; return; }
    status.textContent = list.length ? `${list.length} private transaction${list.length === 1 ? '' : 's'}` : 'No private transactions yet.';
    items.replaceChildren();
    for (const entry of list.slice().sort((a, b) => b.created_at_ms - a.created_at_ms)) {
      const card = node('section', null, { class: 'wb-recipient' });
      card.append(node('strong', entry.label || entry.state.replaceAll('_', ' ')),
        node('code', entry.tx_id, { class: 'wb-address' }),
        node('p', `${entry.state.replaceAll('_', ' ')} · ${decimal(entry.fee_nano_erg)} ERG fee · ${entry.size_bytes} bytes`, { class: 'wb-note' }),
        node('p', `${entry.input_ids.length} input${entry.input_ids.length === 1 ? '' : 's'}${['queued', 'in_candidate'].includes(entry.state) ? ' reserved' : ''} · expiry: ${time(entry.expires_at_ms)}${entry.expires_at_height ? ` · last height ${entry.expires_at_height}` : ''} · priority ${entry.priority}`, { class: 'wb-note' }));
      if (entry.reason) card.append(node('p', entry.reason, { class: 'wb-note' }));
      if (entry.mined_height !== null) card.append(node('p', `Mined at height ${entry.mined_height}`, { class: 'wb-note' }));
      if (['queued', 'in_candidate', 'conflicted'].includes(entry.state)) {
        const cancel = node('button', 'Cancel pending transaction', { type: 'button', class: 'btn btn--sm' });
        cancel.addEventListener('click', async () => {
          if (busy || !window.confirm('Withdraw this transaction from your miner and release its reserved inputs?')) return;
          busy = true; cancel.disabled = true;
          try {
            const response = await api.cancelPrivate(entry.tx_id);
            if (disposed || !active()) return;
            if (!response?.ok) status.textContent = error(response);
            else await load();
          } finally { busy = false; if (!disposed) cancel.disabled = false; }
        });
        card.append(cancel);
      }
      items.append(card);
    }
  }
  refresh.addEventListener('click', () => { if (!busy) void load(); });
  submit.addEventListener('click', async () => {
    if (busy || !consent.checked || !active()) return;
    const hex = bytes.value.trim();
    if (!/^(?:[a-f0-9]{2})+$/i.test(hex)) { status.textContent = 'Enter the signed transaction as hexadecimal bytes.'; return; }
    const deadline = expiry.value ? new Date(expiry.value).getTime() : null;
    if (deadline !== null && (!Number.isSafeInteger(deadline) || deadline <= Date.now())) { status.textContent = 'Choose an expiry time in the future.'; return; }
    const height = expiryHeight.value ? Number(expiryHeight.value) : null, rank = Number(priority.value);
    if (height !== null && (!Number.isSafeInteger(height) || height < 1 || height > 4294967295)) { status.textContent = 'Choose a valid last eligible block height.'; return; }
    if (!Number.isSafeInteger(rank) || rank < -2147483648 || rank > 2147483647) { status.textContent = 'Queue priority must be a signed 32-bit integer.'; return; }
    busy = true; submit.disabled = true;
    try {
      const response = await api.importPrivate(hex, { expires_at_ms: deadline, expires_at_height: height, priority: rank, label: label.value.trim() || null });
      if (disposed || !active()) return;
      if (!response?.ok) status.textContent = error(response);
      else { bytes.value = ''; consent.checked = false; await load(); }
    } finally { busy = false; if (!disposed) submit.disabled = !consent.checked; }
  });
  const timer = setInterval(() => { if (!disposed && !busy && active()) void load(); }, 5000);
  void load();
  return { refresh: load, dispose() { disposed = true; version++; clearInterval(timer); host.replaceChildren(); } };
}
