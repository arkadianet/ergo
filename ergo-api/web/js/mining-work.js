import { num, dur, truncMiddle, erg, bytes } from './format.js';
import { promptAuthorize } from './auth.js';
import { copyBtn } from './table.js';

export function miningWorkState(result) {
  if (!result) return { label: 'Checking candidate', tone: 'neutral', detail: 'Waiting for a response from the mining endpoint.' };
  if (result.reason === 'preview-read-only') return { label: 'Hidden in design preview', tone: 'neutral', detail: 'Mining work requires authorization. Use the running node’s UI to inspect the candidate.' };
  if (result.status === 401 || result.status === 403) {
    if (result.reason === 'api-key-not-configured') return { label: 'API key not configured', tone: 'warn', detail: 'Configure [api.security] api_key_hash on the node to inspect mining work.' };
    return { label: 'Authorization required', tone: 'neutral', detail: 'The node protects mining work with its operator API key. Candidate availability is unknown until authorized.', authorize: true };
  }
  if (result.ok && typeof result.data?.msg === 'string' && result.data.msg.length) return { label: 'Candidate available', tone: 'ok', candidate: result.data };
  if (result.status === 503 && result.detail?.includes('waiting for a recent block after startup')) return { label: 'Waiting for a fresh block', tone: 'neutral', detail: 'After a restart, mining waits for a newly applied, recent network block. It starts automatically; search indexing and an empty mempool do not block it.' };
  if (result.status === 503) return { label: 'Candidate not ready', tone: 'warn', detail: result.detail || 'The node reports mining work is temporarily unavailable. This page retries automatically.' };
  if (result.status === 404) return { label: 'Mining endpoint unavailable', tone: 'neutral', detail: 'The node did not expose this mining route. Check its mining configuration and API version.' };
  if (!result.status || result.status === 502 || result.status === 504) return { label: 'Candidate request failed', tone: 'warn', detail: 'The mining endpoint could not be reached or timed out. Candidate availability is unknown; this page retries automatically.' };
  return { label: 'Candidate request failed', tone: 'warn', detail: result.detail || `Unexpected mining response (HTTP ${result.status}).` };
}

function element(tag, cls, text) {
  const el = document.createElement(tag);
  if (cls) el.className = cls;
  if (text != null) el.textContent = text;
  return el;
}

function row(label, value, fullValue) {
  const wrap = element('div', 'ov-kv');
  const val = element('span', 'mining-work__value', value);
  if (fullValue) {
    val.title = fullValue;
    const copy = copyBtn(fullValue);
    copy.setAttribute('aria-label', `Copy ${label.toLowerCase()}`);
    val.append(copy);
  }
  wrap.append(element('span', '', label), val);
  return wrap;
}

export function candidateMetrics(candidate) {
  const m = candidate?.metrics;
  if (!m || typeof m !== 'object') return null;
  const integer = (value) => Number.isSafeInteger(value) && value >= 0 ? value : null;
  const selected = integer(m.selected_transaction_count);
  const total = integer(m.transaction_count);
  return {
    selected: selected != null && total != null && selected > total ? null : selected,
    total,
    fees: typeof m.fees_nano_erg === 'string' && /^\d+$/.test(m.fees_nano_erg) ? BigInt(m.fees_nano_erg) : null,
    size: integer(m.transactions_size_bytes), maxSize: integer(m.max_block_size_bytes),
    cost: integer(m.validation_cost), maxCost: integer(m.max_block_cost),
  };
}

function metricsView(metrics) {
  const list = element('dl', 'mining-work__metrics');
  const cell = (label, value, note, usage, limit) => {
    const wrap = element('div', 'mining-work__metric');
    wrap.append(element('dt', '', label), element('dd', '', value), element('small', '', note));
    if (usage != null && limit > 0) {
      const gauge = element('div', 'mining-work__gauge');
      gauge.title = `${num(usage)} / ${num(limit)} · ${(100 * usage / limit).toFixed(1)}%`;
      gauge.setAttribute('aria-hidden', 'true');
      const fill = element('div');
      fill.style.width = `${Math.min(100, 100 * usage / limit)}%`;
      gauge.append(fill);
      wrap.append(gauge);
    }
    list.append(wrap);
  };
  const { selected, total, fees, size, maxSize, cost, maxCost } = metrics;
  cell('Selected transactions', num(selected), total == null ? 'Mempool transactions retained' : `${num(total)} total, including system transactions`);
  cell('Collected fees', fees == null ? '—' : `${erg(fees).replace(/\.0$/, '')} ERG`, 'Excludes emission and rent self-claims');
  cell('Transaction section', bytes(size), maxSize > 0 ? `${bytes(maxSize)} block-size limit` : 'Size limit unavailable', size, maxSize);
  cell('Validation cost', num(cost), maxCost > 0 ? `${num(maxCost)} block-cost limit` : 'Cost limit unavailable', cost, maxCost);
  return list;
}

export function miningWork(result, { observedAt, detailsOpen = false } = {}) {
  const work = miningWorkState(result);
  const host = element('div', 'mining-work');
  host.dataset.tone = work.tone;
  const status = row('Work status', work.label);
  status.classList.add('mining-work__status');
  host.append(status);
  if (work.detail) host.append(element('p', 'mining-work__note', work.detail));
  if (work.authorize) {
    const button = element('button', 'btn btn--ghost btn--sm', 'Authorize to inspect');
    button.type = 'button';
    button.onclick = promptAuthorize;
    host.append(button);
  }
  const c = work.candidate;
  if (!c) return host;
  host.append(row('Candidate height', num(c.h)), row('Template sequence', num(c.template_seq)));
  const metrics = candidateMetrics(c);
  if (metrics) host.append(metricsView(metrics));
  else host.append(element('p', 'mining-work__note', 'This node does not supply template metrics. A node build with candidate metrics is needed to show selected transactions, fees, size and validation cost.'));
  const details = element('details', 'mining-work__details');
  details.open = detailsOpen;
  details.append(element('summary', '', 'Work details'));
  const body = element('div', 'mining-work__fields');
  body.append(row('Job ID', truncMiddle(c.msg, 8, 8), c.msg));
  if (c.pk) body.append(row('Miner public key', truncMiddle(c.pk, 8, 8), c.pk));
  const target = Number(c.b);
  body.append(row('PoW target · approximate', Number.isFinite(target) && target > 0 ? target.toExponential(4) : '—'));
  body.append(row('Discard previous jobs', c.clean_jobs === true ? 'Requested' : c.clean_jobs === false ? 'Not requested' : '—'));
  body.append(row('Mandatory transaction proof', c.proof == null ? 'Not supplied' : 'Present'));
  if (observedAt) body.append(row('Template observed', `${dur(Math.max(0, Math.floor((Date.now() - observedAt) / 1000)))} ago`));
  body.append(element('p', 'mining-work__note', 'Observed time is local to this page, not the template creation time.'));
  if (metrics) body.append(element('p', 'mining-work__note', 'Metrics describe this exact template after transaction selection and trimming. Total transactions include emission, rent self-claims and fee collection when present. Size includes transaction-section framing, excluding the header, extension and proofs. Validation cost uses protocol block-cost units, not milliseconds.'));
  details.append(body);
  host.append(details);
  return host;
}
