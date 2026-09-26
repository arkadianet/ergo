// Public reads resolve failed requests to null. Mining work and wallet reads
// preserve response status/reason so authorization failures stay distinguishable
// from unavailable data. The API key (if set) is read per-call.
//
// auth.report() lets the Authorize chip re-verify opportunistically: a 403
// with an auth reason updates the state; a 2xx from a *gated* request confirms it
// (a 2xx from a public read proves nothing — see auth.js).
import { getApiKey, report } from './auth.js';

async function getJson(path) {
  try {
    const headers = {};
    const key = getApiKey();
    if (key) headers['api_key'] = key;
    const r = await fetch(path, { cache: 'no-store', headers, signal: AbortSignal.timeout(12000) });
    const error = r.status === 403 ? await r.clone().json().catch(() => null) : null;
    report(r.status, false, key, error?.reason);
    if (!r.ok) return null;
    return await r.json();
  } catch {
    return null;
  }
}

// Public rent reads retain readiness errors instead of turning them into zero.
async function getRentPage(fromHeight, toHeight, offset, limit) {
  try {
    const r = await fetch(`/blockchain/storageRent/maturesInRange?fromHeight=${fromHeight}&toHeight=${toHeight}&offset=${offset}&limit=${limit}&sortDirection=asc`, {
      cache: 'no-store', signal: AbortSignal.timeout(12000),
    });
    const data = await r.json().catch(() => null);
    return { ok: r.ok, status: r.status, data, reason: data?.reason ?? null };
  } catch { return { ok: false, status: 0, data: null, reason: 'request-failed' }; }
}

// Mining reads are operator-gated. Preserve the response envelope so a 403
// cannot masquerade as the node having no candidate (503).
async function getMiningCandidate() {
  const key = getApiKey();
  try {
    const r = await fetch('/mining/candidate', {
      cache: 'no-store', headers: key ? { api_key: key } : {}, signal: AbortSignal.timeout(12000),
    });
    const data = await r.json().catch(() => null);
    report(r.status, true, key, data?.reason);
    // An in-flight response for an old key must not expose its work after
    // authorization is cleared or replaced in this tab.
    if (key !== getApiKey()) return null;
    return { ok: r.ok, status: r.status, data, reason: data?.reason ?? null, detail: data?.detail ?? null };
  } catch {
    return { ok: false, status: 0, data: null, reason: 'request-failed', detail: null };
  }
}

// POST a JSON body with the operator's api_key (auth-gated writes). Resolves to
// `{ ok, status, detail }` so callers can surface the precise rejection (403
// missing/invalid key, 409 mining disabled, 400 bad target) in the UI.
async function postJson(path, body) {
  try {
    const headers = { 'content-type': 'application/json' };
    const key = getApiKey();
    if (key) headers['api_key'] = key;
    const r = await fetch(path, { method: 'POST', headers, body: JSON.stringify(body) });
    const error = r.status === 403 ? await r.clone().json().catch(() => null) : null;
    report(r.status, true, key, error?.reason);
    if (r.ok) return { ok: true, status: r.status };
    let detail = null;
    try {
      detail = (await r.json()).detail;
    } catch {
      /* non-JSON error body */
    }
    return { ok: false, status: r.status, detail };
  } catch (e) {
    return { ok: false, status: 0, detail: String(e) };
  }
}

// Wallet routes need the raw status + the {reason|detail} envelope (403 ->
// re-authorize, wallet_locked, etc.), so they don't use getJson/postJson.
// Returns { ok, status, data, reason }; reports status to auth (gated).
async function walletReq(path, opts = {}) {
  const headers = { ...(opts.headers || {}) };
  const key = getApiKey();
  if (key) headers['api_key'] = key;
  try {
    const r = await fetch(path, { cache: 'no-store', ...opts, headers });
    let data = null;
    let reason = null;
    const text = await r.text();
    if (text) {
      try {
        data = JSON.parse(text);
        reason = data.reason || data.detail || null;
      } catch {
        /* non-JSON body */
      }
    }
    report(r.status, true, key, data?.reason);
    return { ok: r.ok, status: r.status, data, reason };
  } catch (e) {
    return { ok: false, status: 0, data: null, reason: String(e) };
  }
}

function walletPost(path, body) {
  return walletReq(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}

export const api = {
  status: () => getJson('/api/v1/status'),
  info: () => getJson('/api/v1/info'),
  sync: () => getJson('/api/v1/sync'),
  tip: () => getJson('/api/v1/tip'),
  identity: () => getJson('/api/v1/identity'),
  host: () => getJson('/api/v1/host'),
  indexedHeight: () => getJson('/blockchain/indexedHeight'),
  // Operator health superset of indexedHeight (self-repair markers + totals).
  // 404s on indexer-less wiring — the UI reads null as "extra-index disabled".
  indexerStatus: () => getJson('/api/v1/indexer/status'),
  recentBlocks: (n = 10) => getJson(`/api/v1/blocks/recent?n=${n}`),
  // Operator event feed (bounded ring tail). `since` = last-seen seq.
  events: (since = 0) => getJson(`/api/v1/events${since ? `?since=${since}` : ''}`),
  // Mining surface — routes mount only when mining is wired (404 = off).
  // candidate is cheap on repeat calls (same-tip template cache node-side).
  miningCandidate: getMiningCandidate,
  miningRewardAddress: () => getJson('/mining/rewardAddress'),
  miningRewardPublicKey: () => getJson('/mining/rewardPublicKey'),
  // Network mining landscape: last-`window` headers folded by miner pk,
  // addresses derived server-side. Rides the chain reader (404 = old node).
  minerStats: (window = 720) => getJson(`/api/v1/mining/minerStats?window=${window}`),
  // Emission schedule facts at a height ({minerReward, reemitted, …} nanoERG).
  emissionAt: (height) => getJson(`/emission/at/${height}`),
  storageRentMatures: getRentPage,
  difficultyHistory: (b = 60) => getJson(`/api/v1/difficulty/history?blocks=${b}`),
  // Mempool wait-time histogram: bins+1 buckets of {nTxns, totalFee}.
  poolHistogram: (bins = 10, maxtimeMs = 3_600_000) =>
    getJson(`/transactions/poolHistogram?bins=${bins}&maxtime=${maxtimeMs}`),
  peers: () => getJson('/api/v1/peers'),
  mempoolSummary: () => getJson('/api/v1/mempool/summary'),
  mempoolTransactions: () => getJson('/api/v1/mempool/transactions'),
  txDetail: (id) => getJson(`/api/v1/transactions/${id}/detail`),
  votes: () => getJson('/api/v1/votes'),
  votesHistory: () => getJson('/api/v1/votes/history'),
  // Auth-gated write: `votes` is the full desired set (replaces current).
  setVotes: (votes) => postJson('/api/v1/votes', { votes }),
  // Wallet section: api_key-gated; each returns { ok, status, data, reason }.
  // /lock and /deriveNextKey are GET routes (see ergo-api wallet/mod.rs).
  wallet: {
    status: () => walletReq('/wallet/status'),
    init: (body) => walletPost('/wallet/init', body),
    restore: (body) => walletPost('/wallet/restore', body),
    unlock: (pass) => walletPost('/wallet/unlock', { pass }),
    lock: () => walletReq('/wallet/lock'),
    balances: () => walletReq('/wallet/balances'),
    addresses: () => walletReq('/wallet/addresses'),
    deriveNextKey: () => walletReq('/wallet/deriveNextKey'),
    updateChangeAddress: (address) => walletPost('/wallet/updateChangeAddress', { address }),
    send: (requests) => walletPost('/wallet/payment/send', requests),
    // Native endpoint: sweep matured miner-reward boxes into one P2PK output,
    // EIP-27-correct (burns the re-emission token, pays pay-to-reemission).
    retrieveRewards: (body) => walletPost('/api/v1/wallet/rewards/retrieve', body),
  },
};

export { getJson };
