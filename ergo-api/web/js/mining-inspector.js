import { api } from './api-client.js';
import { subscribe, promptAuthorize } from './auth.js';
import { num, erg, bytes, truncMiddle } from './format.js';
import { makeTable, copyBtn } from './table.js';

const el = (tag, cls, text) => {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text != null) node.textContent = text;
  return node;
};
const money = (value) => typeof value === 'string' && /^\d+$/.test(value) ? `${erg(BigInt(value))} ERG` : '—';
const idNode = (id) => { const node = el('span', 'mining-inspector__id', truncMiddle(id, 8, 8)); node.title = id; node.append(copyBtn(id)); return node; };

export function matchesTemplate(details, candidate) {
  return !!details && !!candidate && details.msg === candidate.msg && details.template_seq === candidate.template_seq;
}

// Exclusion reasons recorded by candidate assembly. A `required_` prefix marks
// a block-policy requirement the template leaves out; mining continues.
const EXCLUSION_REASONS = {
  excluded_by_policy: 'excluded by your block policy',
  unavailable: 'not in the mempool or private queue (mined, replaced or expired)',
  excluded_ancestor: 'depends on a transaction your policy excludes',
  cost_budget: 'did not fit the remaining validation cost',
  size_budget: 'did not fit the remaining block size',
  input_conflict: 'an input is already spent in this block',
  input_unavailable: 'an input is spent or not yet available',
  data_input_unavailable: 'a data input is not available',
  malformed_transaction: 'could not be decoded',
  consensus_validation_failed: 'failed validation for this block',
  final_fee_or_section_budget: 'trimmed so the fee transaction and block section fit',
};
const REQUIRED = 'required_';

export const isUnmetRequirement = (entry) => String(entry?.reason ?? '').startsWith(REQUIRED);

export function exclusionLabel(reason) {
  const text = String(reason ?? '');
  const required = text.startsWith(REQUIRED);
  const base = required ? text.slice(REQUIRED.length) : text;
  const detail = EXCLUSION_REASONS[base] || base.replaceAll('_', ' ') || 'unknown reason';
  return required ? `Required, not included: ${detail}` : detail.charAt(0).toUpperCase() + detail.slice(1);
}

export function inspectorMessage(result) {
  if (!result) return 'Waiting for a candidate to inspect.';
  if (result.status === 401 || result.status === 403) return 'Authorize to inspect transaction contents and miner proceeds.';
  if (result.status === 404) return 'This template is no longer retained. Select the current candidate.';
  return result.reason || result.data?.detail || 'Candidate details are unavailable. Retrying automatically.';
}

function kv(label, value) {
  const row = el('div', 'ov-kv');
  row.append(el('span', '', label), value instanceof Node ? value : el('strong', '', value));
  return row;
}

function section(title, open = false) {
  const root = el('details', 'mining-inspector__section');
  root.open = open;
  root.append(el('summary', '', title));
  const body = el('div', 'mining-inspector__section-body');
  root.append(body);
  return { root, body };
}

function assetsView(assets, empty = 'None') {
  const list = el('div', 'mining-inspector__assets');
  if (!assets?.length) list.append(el('span', 'muted', empty));
  for (const asset of assets || []) {
    const row = el('div', 'mining-inspector__asset');
    row.append(idNode(asset.token_id), el('span', '', `${asset.amount} units`));
    list.append(row);
  }
  return list;
}

function pagedTable(host, rows, columns, options = {}) {
  const controls = el('div', 'mining-inspector__pager');
  const tableHost = el('div');
  host.append(controls, tableHost);
  let page = 0;
  const size = 50;
  const table = makeTable(tableHost, columns, options);
  const draw = () => {
    table.update(rows.slice(page * size, (page + 1) * size));
    controls.replaceChildren(el('span', 'muted', `${num(rows.length)} entries · ${num(page * size + (rows.length ? 1 : 0))}–${num(Math.min(rows.length, (page + 1) * size))}`));
    for (const [label, direction] of [['Previous', -1], ['Next', 1]]) {
      const button = el('button', 'btn btn--ghost btn--sm', label);
      button.type = 'button';
      button.disabled = direction < 0 ? page === 0 : (page + 1) * size >= rows.length;
      button.onclick = () => { page += direction; draw(); };
      controls.append(button);
    }
  };
  draw();
}

function transactionDetail(tx) {
  const body = el('div', 'mining-inspector__tx-detail');
  body.append(kv('Transaction ID', idNode(tx.id)));
  for (const [label, ids] of [['Inputs', tx.input_ids], ['Data inputs', tx.data_input_ids]]) {
    const block = el('div');
    block.append(el('h3', '', label));
    for (const id of ids || []) block.append(idNode(id));
    if (!ids?.length) block.append(el('span', 'muted', 'None'));
    body.append(block);
  }
  const outputs = el('div');
  outputs.append(el('h3', '', 'Outputs'));
  for (const output of tx.outputs || []) {
    const row = el('div', 'mining-inspector__output');
    row.append(kv(`Output ${output.index}`, money(output.value_nano_erg)), kv('Box ID', idNode(output.box_id)), kv('Created at height', num(output.creation_height)), assetsView(output.assets));
    const script = section('Output script');
    script.body.append(el('code', 'mining-inspector__hex', output.ergo_tree));
    row.append(script.root);
    outputs.append(row);
  }
  body.append(outputs);
  const signed = section('Signed transaction bytes');
  const textarea = el('textarea', 'input mining-inspector__bytes');
  textarea.readOnly = true;
  textarea.rows = 4;
  textarea.value = tx.bytes;
  textarea.setAttribute('aria-label', 'Canonical signed transaction bytes');
  signed.body.append(textarea, copyBtn(tx.bytes));
  body.append(signed.root);
  return body;
}

function detailsView(details) {
  const root = el('div', 'mining-inspector');
  const context = el('div', 'mining-inspector__context');
  context.append(kv('Template', `${num(details.template_seq)} · ${details.status.replaceAll('_', ' ')}`), kv('Height', num(details.height)), kv('Published', new Date(details.published_at_ms).toLocaleString()), kv('Build', `${details.build_mode} · ${details.build_reason}`), kv('Parent block', idNode(details.parent_id)));
  root.append(context);
  if (details.build_mode === 'initial') root.append(el('p', 'muted', 'The first template after a new block contains emission only. The enriched refresh adds selected transactions and storage rent.'));
  const unmet = details.exclusions.filter(isUnmetRequirement);
  if (unmet.length) root.append(el('p', 'mining-inspector__burn', `${num(unmet.length)} required ${unmet.length === 1 ? 'transaction is' : 'transactions are'} not in this template; mining continues without ${unmet.length === 1 ? 'it' : 'them'}. Requirements stay in your block policy until you clear them. See the excluded transactions below.`));
  const rewards = el('div', 'mining-inspector__rewards');
  for (const [label, amount] of [['Emission', details.rewards.emission_nano_erg], ['Transaction fees', details.rewards.fees_nano_erg], ['Storage rent', details.rewards.rent_nano_erg], ['Total miner proceeds', details.rewards.total_nano_erg]]) rewards.append(kv(label, money(amount)));
  root.append(rewards);
  const payouts = section('Payout boxes and spendability');
  for (const payout of details.rewards.outputs || []) {
    const box = el('div', 'mining-inspector__output');
    box.append(kv(payout.category, money(payout.value_nano_erg)), kv('Payout address', idNode(payout.address)), kv('Spendable from height', num(payout.spendable_at_height)), kv('Output box', idNode(payout.box_id)), assetsView(payout.assets));
    payouts.body.append(box);
  }
  root.append(payouts.root);
  const txs = section(`Candidate transactions · ${num(details.transactions.length)}`, true);
  pagedTable(txs.body, details.transactions, [
    { key: 'index', label: 'Order', width: 65, sort: (t) => t.index },
    { key: 'category', label: 'Source', width: 95 },
    { key: 'id', label: 'Transaction', render: (t) => idNode(t.id) },
    { key: 'fee_nano_erg', label: 'Fee', width: 130, align: 'right', render: (t) => money(t.fee_nano_erg), sort: (t) => BigInt(t.fee_nano_erg) },
    { key: 'size_bytes', label: 'Size', width: 90, align: 'right', render: (t) => bytes(t.size_bytes) },
    { key: 'validation_cost', label: 'Cost', width: 95, align: 'right', render: (t) => num(t.validation_cost) },
  ], { rowKey: (t) => t.id, renderDetail: transactionDetail, initialSort: { key: 'index', dir: 1 }, label: 'Transactions in candidate order' });
  root.append(txs.root);
  const rent = section(`Storage rent · ${num(details.rent.selected_boxes)} selected boxes`);
  for (const [label, value] of [['Eligible boxes scanned', num(details.rent.scanned_boxes)], ['Recreated after rent', num(details.rent.recreated_boxes)], ['Fully consumed', num(details.rent.consumed_boxes)], ['Deferred to preserve tokens', num(details.rent.skipped_to_preserve_tokens)], ['ERG collected', money(details.rent.collected_nano_erg)]]) rent.body.append(kv(label, value));
  rent.body.append(el('p', 'muted', 'The scan is bounded by mining policy and the index. It describes this build, including already overdue boxes, and does not count the entire eligible backlog.'));
  rent.body.append(el('h3', '', 'Tokens received by the miner'), assetsView(details.rent.recovered_tokens));
  rent.body.append(el('h3', details.rent.burned_tokens?.length ? 'mining-inspector__burn' : '', 'Tokens burned by this claim'), assetsView(details.rent.burned_tokens, 'None — tokens are preserved.'));
  pagedTable(rent.body, details.rent.claims || [], [
    { key: 'box_id', label: 'Input box', render: (b) => idNode(b.box_id) },
    { key: 'age_blocks', label: 'Age · blocks', width: 115, align: 'right' },
    { key: 'branch', label: 'Action', width: 95 },
    { key: 'input_value_nano_erg', label: 'Original value', width: 140, render: (b) => money(b.input_value_nano_erg), sort: (b) => BigInt(b.input_value_nano_erg) },
    { key: 'collected_nano_erg', label: 'Rent collected', width: 140, render: (b) => money(b.collected_nano_erg), sort: (b) => BigInt(b.collected_nano_erg) },
  ], { rowKey: (b) => b.box_id, renderDetail: (b) => assetsView(b.input_assets), label: 'Storage rent inputs' });
  root.append(rent.root);
  const exclusions = section(`Transactions excluded · ${num(details.exclusions.length)}`, unmet.length > 0);
  for (const entry of [...unmet, ...details.exclusions.filter((e) => !isUnmetRequirement(e))]) {
    const row = kv(exclusionLabel(entry.reason), idNode(entry.transaction_id));
    row.title = entry.reason;
    exclusions.body.append(row);
  }
  if (!details.exclusions.length) exclusions.body.append(el('p', 'muted', 'No recorded exclusions.'));
  root.append(exclusions.root);
  const protocol = section('Votes and extension commitments');
  protocol.body.append(kv('Header votes · bytes', details.votes.join(', ')), kv('Policy revision', num(details.policy_revision)));
  for (const field of details.extensions) protocol.body.append(kv(field.key, el('code', 'mining-inspector__hex', field.value)));
  root.append(protocol.root);
  const download = el('button', 'btn btn--ghost', 'Export candidate report');
  download.type = 'button';
  download.onclick = () => {
    const url = URL.createObjectURL(new Blob([JSON.stringify(details, null, 2)], { type: 'application/json' }));
    const link = el('a'); link.href = url; link.download = `candidate-${details.height}-${details.template_seq}.json`; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 0);
  };
  root.append(download);
  return root;
}

export function createMiningInspector(host) {
  let current = null;
  let selected = null;
  let result = null;
  let history = null;
  let generation = 0;
  let drawnIdentity = null;

  const draw = () => {
    const signature = `${selected?.msg || 'current'}:${result?.data?.msg || ''}:${result?.data?.template_seq || ''}:${result?.data?.status || ''}:${result?.status || 0}:${result?.reason || ''}:${history?.outcomes?.[0]?.at_ms || 0}:${history?.retained_templates?.[0]?.template_seq || 0}:${history?.chain_tip?.block_id || ''}`;
    if (signature === drawnIdentity) return;
    drawnIdentity = signature;
    host.replaceChildren();
    const bar = el('div', 'mining-inspector__toolbar');
    const select = el('select', 'select'); select.setAttribute('aria-label', 'Inspect mining template');
    const active = el('option', '', 'Current candidate'); active.value = ''; select.append(active);
    for (const template of history?.retained_templates || []) {
      const option = el('option', '', `Template ${template.template_seq} · height ${template.height} · ${template.status.replaceAll('_', ' ')}`);
      option.value = `${template.msg}:${template.template_seq}`;
      select.append(option);
    }
    select.value = selected ? `${selected.msg}:${selected.template_seq}` : '';
    select.onchange = () => {
      selected = select.value ? { msg: select.value.split(':')[0], template_seq: Number(select.value.split(':')[1]) } : null;
      result = null; generation++; draw(); load();
    };
    bar.append(select);
    host.append(bar);
    if (result?.ok && result.data) host.append(detailsView(result.data));
    else {
      host.append(el('p', 'muted', inspectorMessage(result)));
      if (result?.status === 401 || result?.status === 403) {
        const button = el('button', 'btn btn--ghost', 'Authorize'); button.type = 'button'; button.onclick = promptAuthorize; host.append(button);
      }
    }
    const outcomes = section('Local mining outcomes and accounting');
    if (history?.journal_error) outcomes.body.append(el('p', 'mining-inspector__burn', history.journal_error));
    outcomes.body.append(el('p', 'muted', history?.resets_on_restart === false ? 'Submission history is retained across restarts. Acceptance records local application; follow the block link to check its current chain status.' : 'Local submission history is bounded and resets on restart. Acceptance records local application; follow the block link to check its current chain status.'));
    for (const event of history?.outcomes || []) {
      const row = el('div', 'mining-inspector__output');
      const link = event.block_id ? el('a', 'ex-link', truncMiddle(event.block_id, 8, 8)) : el('span', 'muted', 'No block');
      if (event.block_id) link.href = `#explorer/block/${event.block_id}`;
      row.append(kv(`${event.outcome} · ${new Date(event.at_ms).toLocaleString()}`, link));
      if (event.block_id) row.append(kv('Current applied chain', event.canonical === true ? `${num(event.confirmations)} confirmations` : event.canonical === false ? 'Orphaned by a reorg' : 'Not verified'));
      if (event.accounting?.recovered_tokens?.length) row.append(assetsView(event.accounting.recovered_tokens));
      if (event.detail) row.append(el('p', 'muted', event.detail));
      if (event.accounting) for (const [label, amount] of [['Emission', event.accounting.emission_nano_erg], ['Fees', event.accounting.fees_nano_erg], ['Rent', event.accounting.rent_nano_erg]]) row.append(kv(label, money(amount)));
      outcomes.body.append(row);
    }
    if (!history?.outcomes?.length) outcomes.body.append(el('p', 'muted', 'No local solution submissions recorded.'));
    host.append(outcomes.root);
  };

  const load = async () => {
    const target = selected || current;
    if (!target) { draw(); return; }
    const ticket = ++generation;
    const [details, recent] = await Promise.all([api.miningCandidateDetails(target.msg, target.template_seq), api.miningHistory()]);
    if (ticket !== generation) return;
    result = details;
    if (details?.ok && !matchesTemplate(details.data, target)) result = { ok: false, status: 0, reason: 'The response did not match the requested template. Retrying automatically.' };
    history = recent?.ok ? recent.data : null;
    draw();
  };

  subscribe((state) => {
    if (state !== 'authorized') { generation++; result = { ok: false, status: 403, reason: 'Authorization required.' }; history = null; selected = null; drawnIdentity = null; draw(); }
  });
  return {
    async refresh(candidateResult) {
      if (!candidateResult?.ok || !candidateResult.data) { generation++; current = null; result = candidateResult; history = null; drawnIdentity = null; draw(); return; }
      current = candidateResult.data;
      await load();
    },
  };
}
