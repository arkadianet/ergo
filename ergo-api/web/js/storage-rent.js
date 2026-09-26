import { erg, num } from './format.js';

const STORAGE_PERIOD = 1_051_200;
export const RENT_WINDOW = 720;
const PAGE_SIZE = 1_024;
const MAX_BOXES = 16_384;
const RETRY_MS = 30_000;
const idPattern = /^[0-9a-f]{64}$/i;
const tipKey = (tip) => `${tip?.height}:${tip?.header_id}`;

export function rentAccess({ tip, indexer, identity, reachable }) {
  if (reachable === false) return 'offline';
  if (identity?.extra_index_enabled === false) return 'disabled';
  if (indexer?.status === 'halted') return 'halted';
  if (indexer?.repair?.pending || indexer?.repair?.skipped > 0 || indexer?.repair?.driftSkips > 0) return 'degraded';
  if (indexer?.status === 'syncing') return 'syncing';
  if (indexer?.status !== 'caughtUp' || !Number.isSafeInteger(tip?.height) || tip.height < 0 || tip.height > 0xffff_ffff - RENT_WINDOW ||
      !idPattern.test(tip.header_id ?? '') || indexer.indexedHeight !== tip.height ||
      indexer.fullHeight !== tip.height) return 'unavailable';
  return null;
}

// Sum the node's consensus-aware rentOwed, never box balances or fee × size.
// Token IDs describe holdings in maturing boxes, not a miner token payout.
export function summarizeRent(items, height) {
  const next = { rent: 0n, boxes: 0, tokens: new Set() };
  const window = { rent: 0n, boxes: 0, tokens: new Set() };
  const seen = new Set();
  let excluded = 0;
  for (const box of items) {
    const boxId = String(box.boxId ?? '').toLowerCase();
    const maturity = box.creationHeight + STORAGE_PERIOD;
    if (!idPattern.test(boxId) || seen.has(boxId) ||
        !Number.isSafeInteger(box.creationHeight) || box.creationHeight < 0 ||
        maturity < height + 1 || maturity > height + RENT_WINDOW ||
        !Number.isSafeInteger(box.rentOwed) || box.rentOwed < 0 ||
        typeof box.practicallyCollectable !== 'boolean' || !Array.isArray(box.assets) ||
        box.assets.some((asset) => !idPattern.test(asset.tokenId ?? '')) ||
        (!box.practicallyCollectable && box.rentOwed !== 0)) throw new Error('invalid-rent-data');
    seen.add(boxId);
    if (!box.practicallyCollectable) excluded++;
    for (const bucket of maturity === height + 1 ? [next, window] : [window]) {
      bucket.rent += BigInt(box.rentOwed);
      bucket.boxes++;
      box.assets.forEach((asset) => bucket.tokens.add(asset.tokenId.toLowerCase()));
    }
  }
  return {
    height, fromHeight: height + 1, toHeight: height + RENT_WINDOW, excluded,
    next: { ...next, tokens: next.tokens.size },
    window: { ...window, tokens: window.tokens.size },
  };
}

export async function loadRentForecast(api, tip) {
  const rows = [];
  let total = null;
  const started = Date.now();
  do {
    if (Date.now() - started > 20_000) return { state: 'busy' };
    const response = await api.storageRentMatures(tip.height + 1, tip.height + RENT_WINDOW, rows.length, PAGE_SIZE);
    if (!response?.ok) {
      const reason = response?.reason;
      return { state: reason === 'indexer-syncing' ? 'syncing' : reason === 'indexer-halted' ? 'halted' : response?.status === 404 ? 'unsupported' : 'unavailable' };
    }
    const page = response.data;
    if (!Array.isArray(page?.items) || !Number.isSafeInteger(page.total) || page.total < 0 ||
        (total != null && page.total !== total) || page.items.length > PAGE_SIZE) return { state: 'changed' };
    total = page.total;
    if (total > MAX_BOXES) return { state: 'large', boxes: total };
    if (rows.length + page.items.length > total || (page.items.length === 0 && rows.length < total)) return { state: 'changed' };
    rows.push(...page.items);
  } while (rows.length < total);
  // Offset pages and token lookups are separate database reads. Reject a
  // moving chain (including a same-height reorg), rather than mix snapshots.
  const [after, indexer] = await Promise.all([api.tip(), api.indexerStatus()]);
  if (tipKey(after?.best_full_block) !== tipKey(tip)) return { state: 'changed' };
  const blocked = rentAccess({ tip, indexer });
  if (blocked) return { state: blocked };
  try { return { state: 'ready', ...summarizeRent(rows, tip.height), asOf: Date.now() }; }
  catch { return { state: 'unavailable' }; }
}

// One bounded scan per full-block identity. Failed reads retry after a pause;
// leaving a ready index invalidates in-flight work and previously shown totals.
export function createRentSource(api) {
  let value = { state: 'loading' }, key = null, pending = null, generation = 0, attemptedAt = 0;
  return {
    get: () => value,
    refresh(context) {
      const blocked = rentAccess(context);
      if (blocked) {
        generation++; key = null; pending = null;
        value = { state: blocked };
        return Promise.resolve(value);
      }
      const nextKey = tipKey(context.tip);
      if (key === nextKey) {
        if (pending) return pending;
        if (value.state === 'ready' || Date.now() - attemptedAt < RETRY_MS) return Promise.resolve(value);
      }
      key = nextKey;
      const request = ++generation;
      attemptedAt = Date.now();
      value = { state: 'loading' };
      pending = loadRentForecast(api, context.tip).catch(() => ({ state: 'unavailable' })).then((result) => {
        if (generation === request) { value = result; pending = null; }
        return value;
      });
      return pending;
    },
  };
}

const states = {
  loading: ['Calculating', 'Reading the upcoming rent window…'],
  syncing: ['Waiting for index', 'Rent and token totals will appear automatically when the search index catches up.'],
  disabled: ['Index required', 'Enable the extra index to calculate rent and token totals.'],
  halted: ['Index halted', 'Resolve the reported index issue before rent totals can be calculated.'],
  degraded: ['Index incomplete', 'Index repair or skipped entries prevent reliable rent totals.'],
  offline: ['Node offline', 'Reconnect to the node to calculate the upcoming rent window.'],
  unavailable: ['Unavailable', 'The node has not returned a complete, current rent window. Retrying automatically.'],
  unsupported: ['API unavailable', 'This node does not expose the rent-maturity API.'],
  changed: ['Chain changed', 'The chain changed during the read. Recalculating on the next refresh.'],
  busy: ['Calculation paused', 'This window took too long to read. Retrying automatically.'],
  large: ['Window too large', `This window exceeds the dashboard’s ${num(MAX_BOXES)}-box scan limit. Partial totals are not shown.`],
};

export function rentForecastView(forecast, detailsOpen = false) {
  const e = (tag, cls, text) => {
    const element = document.createElement(tag);
    if (cls) element.className = cls;
    if (text != null) element.textContent = text;
    return element;
  };
  const ready = forecast?.state === 'ready';
  const root = e('section', 'panel ov-rent');
  root.setAttribute('aria-label', 'Upcoming storage rent');
  const head = e('div', 'ov-rent__head');
  head.append(e('h2', 'panel__title', 'Upcoming storage rent'), e('span', 'ov-rent__status', ready ? `As of block ${num(forecast.height)}` : states[forecast?.state]?.[0] || 'Unavailable'));
  const metrics = e('div', 'ov-rent__metrics');
  const amount = (nano) => `${erg(nano).replace(/\.0$/, '')} ERG`;
  const metric = (label, value, detail) => {
    const cell = e('div', 'ov-rent__metric');
    cell.append(e('span', 'ov-rent__label', label), e('strong', 'ov-rent__value', value), e('span', 'ov-rent__detail', detail));
    metrics.append(cell);
  };
  metric('Rent maturing · next block', ready ? amount(forecast.next.rent) : '—', ready ? `${num(forecast.next.boxes)} boxes · ${num(forecast.next.tokens)} distinct tokens · height ${num(forecast.fromHeight)}` : 'Newly eligible at the next local height');
  metric('Rent maturing · next 720 blocks', ready ? amount(forecast.window.rent) : '—', ready ? `${num(forecast.window.boxes)} boxes · heights ${num(forecast.fromHeight)}–${num(forecast.toHeight)}` : 'Includes the next block');
  metric('Distinct tokens · next 720 blocks', ready ? num(forecast.window.tokens) : '—', 'Unique token IDs held in those boxes');
  root.append(head, metrics);
  if (!ready) root.append(e('p', 'ov-rent__notice', states[forecast?.state]?.[1] || states.unavailable[1]));
  const details = e('details', 'ov-rent__explanation');
  details.open = detailsOpen;
  details.append(e('summary', null, 'Eligibility estimates · how to read these figures'));
  details.append(e('p', null, 'Newly eligible boxes only; already-overdue rent is excluded. The 720-block window includes the next block. Amounts use currently unspent boxes and the node’s latest known storage-rent parameters. Spending or parameter changes can alter them; collection is not guaranteed.'));
  details.append(e('p', null, 'Distinct tokens counts each token ID once across the window, including tokens in boxes that are impractical to collect. It measures token types held in those boxes, not token units or a guaranteed miner payout. Rent amounts use the node’s collectable estimate before transaction costs.'));
  if (ready && forecast.excluded) details.append(e('p', null, `${num(forecast.excluded)} boxes flagged as impractical to collect contribute no ERG to the estimate.`));
  root.append(details);
  return root;
}
