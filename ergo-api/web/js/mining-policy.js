import { getApiKey, report, subscribe } from './auth.js';

let unsubscribe = null;
const ids = (text) => text.trim() ? text.trim().split(/[\s,]+/).map((id) => id.toLowerCase()) : [];

export function policyDraft(form) {
  const fraction = (name) => {
    const text = form.elements[name].value.trim();
    const percentage = Number(text);
    if (!text || !Number.isFinite(percentage) || percentage < 0 || percentage > 100) {
      throw new Error('Budget percentages must be between 0 and 100.');
    }
    return Math.round(percentage * 100);
  };
  const required = ids(form.elements.required.value);
  const excluded = ids(form.elements.excluded.value);
  const bundles = form.elements.bundles.value.split('\n').filter((line) => line.trim()).map(ids);
  if ([...required, ...excluded, ...bundles.flat()].some((id) => !/^[a-f0-9]{64}$/.test(id))) {
    throw new Error('Each transaction ID must contain 64 hexadecimal characters.');
  }
  if (required.length + bundles.flat().length > 1024 || excluded.length > 1024 || bundles.length > 128) {
    throw new Error('Use at most 1,024 required IDs, 1,024 excluded IDs and 128 bundles.');
  }
  if ([...required, ...bundles.flat()].some((id) => excluded.includes(id))) {
    throw new Error('A required transaction cannot also be excluded.');
  }
  return {
    rent_max_cost_basis_points: fraction('rent_cost'),
    rent_max_size_basis_points: fraction('rent_size'),
    private_reserved_cost_basis_points: fraction('private_cost'),
    private_reserved_size_basis_points: fraction('private_size'),
    required_tx_ids: required,
    excluded_tx_ids: excluded,
    required_bundles: bundles,
    rent_token_policy: form.elements.tokens.value,
  };
}

export async function policyRequest(method = 'GET', policy = null) {
  const key = getApiKey();
  if (!key) return { ok: false, detail: 'Authorize with your node API key to manage block contents.' };
  try {
    const response = await fetch('/api/v1/mining/policy', {
      method, cache: 'no-store',
      headers: { api_key: key, 'content-type': 'application/json' },
      ...(policy ? { body: JSON.stringify(policy) } : {}),
      signal: AbortSignal.timeout(12000),
    });
    const data = await response.json().catch(() => null);
    report(response.status, true, key, data?.error?.reason ?? data?.reason);
    if (key !== getApiKey()) return { ok: false, stale: true };
    return { ok: response.ok, data, detail: data?.error?.detail ?? data?.error?.message ?? data?.detail ?? data?.message ?? `Request failed (${response.status}).` };
  } catch {
    return { ok: false, detail: 'Could not reach the mining policy API.' };
  }
}

export function miningPolicy() {
  unsubscribe?.();
  const root = document.createElement('section');
  root.className = 'panel mn-full';
  root.innerHTML = `
    <div class="panel__head"><h2 class="panel__title">Block contents policy</h2></div>
    <div class="panel__body">
      <p class="muted">Set how your candidates use space and validation cost. Required transactions come first, then private transactions; public transactions use the remaining budget.</p>
      <p class="muted" data-policy-status role="status">Loading policy…</p>
      <form data-policy-form hidden>
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px">
          <label>Maximum rent validation cost (%)<input name="rent_cost" type="number" min="0" max="100" step="0.01" required></label>
          <label>Maximum rent block size (%)<input name="rent_size" type="number" min="0" max="100" step="0.01" required></label>
          <label>Reserve validation cost for private and required transactions (%)<input name="private_cost" type="number" min="0" max="100" step="0.01" required></label>
          <label>Reserve block size for private and required transactions (%)<input name="private_size" type="number" min="0" max="100" step="0.01" required></label>
        </div>
        <p class="muted">Reservations limit rent while private or required transactions are waiting, and rent always leaves room for the measured size and cost of required transactions. Mandatory block overhead is deducted, and consensus limits always apply.</p>
        <label>Recovered storage-rent tokens
          <select name="tokens"><option value="preserve">Preserve tokens; defer claims that cannot fit</option><option value="burn_overflow">Allow overflow tokens to be burned</option></select>
        </label>
        <p class="muted" data-token-note>Claims that would lose tokens are left eligible for a later block.</p>
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px;margin:16px 0">
          <label>Required transaction IDs<textarea name="required" rows="3" spellcheck="false" placeholder="One transaction ID per line"></textarea></label>
          <label>Excluded transaction IDs<textarea name="excluded" rows="3" spellcheck="false" placeholder="One transaction ID per line"></textarea></label>
          <label>Mandatory bundles<textarea name="bundles" rows="3" spellcheck="false" placeholder="One bundle per line; separate its IDs with spaces"></textarea></label>
        </div>
        <p class="muted">Required transactions and their available ancestors are selected first, and rent never claims their inputs. Mining never waits for them: a requirement that is unavailable or cannot be included is left out and reported under Candidate contents. Requirements stay in the policy until you clear them, including after they confirm.</p>
        <button class="btn" type="submit">Save block policy</button>
        <button class="btn" type="button" data-policy-reload>Reload saved policy</button>
      </form>
    </div>`;
  const form = root.querySelector('[data-policy-form]');
  const status = root.querySelector('[data-policy-status]');
  let epoch = 0;
  const tokenNote = () => {
    root.querySelector('[data-token-note]').textContent = form.elements.tokens.value === 'burn_overflow'
      ? 'Tokens that exceed payout limits may be permanently burned. The candidate inspector shows the actual amounts.'
      : 'Claims that would lose tokens are left eligible for a later block.';
  };
  function populate(policy) {
    for (const [field, name] of [['rent_max_cost_basis_points', 'rent_cost'], ['rent_max_size_basis_points', 'rent_size'], ['private_reserved_cost_basis_points', 'private_cost'], ['private_reserved_size_basis_points', 'private_size']]) {
      form.elements[name].value = policy[field] / 100;
    }
    form.elements.tokens.value = policy.rent_token_policy;
    form.elements.required.value = policy.required_tx_ids.join('\n');
    form.elements.excluded.value = policy.excluded_tx_ids.join('\n');
    form.elements.bundles.value = policy.required_bundles.map((bundle) => bundle.join(' ')).join('\n');
    tokenNote();
  }
  async function load() {
    const requestEpoch = ++epoch;
    const result = await policyRequest();
    if (requestEpoch !== epoch || result.stale) return;
    if (!result.ok) { form.hidden = true; status.textContent = result.detail; return; }
    populate(result.data);
    form.hidden = false;
    status.textContent = 'Saved policy. Changes persist after a restart.';
  }
  form.onsubmit = async (event) => {
    event.preventDefault();
    let draft;
    try { draft = policyDraft(form); } catch (error) { status.textContent = error.message; return; }
    const button = form.querySelector('[type="submit"]');
    button.disabled = true;
    const requestEpoch = ++epoch;
    const result = await policyRequest('PUT', draft);
    button.disabled = false;
    if (requestEpoch !== epoch || result.stale) return;
    if (result.ok) { populate(result.data); status.textContent = 'Policy saved. Candidates built under the previous policy have been retired.'; }
    else status.textContent = result.detail;
  };
  form.elements.tokens.onchange = tokenNote;
  root.querySelector('[data-policy-reload]').onclick = load;
  let authorizedKey = null;
  unsubscribe = subscribe(() => {
    const key = getApiKey();
    if (key === authorizedKey) return;
    authorizedKey = key;
    if (!key) { ++epoch; form.hidden = true; form.reset(); status.textContent = 'Authorize with your node API key to manage block contents.'; }
    else load();
  });
  if (!getApiKey()) status.textContent = 'Authorize with your node API key to manage block contents.';
  return root;
}
