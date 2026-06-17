// Thin fetch wrapper. Any error/non-2xx/parse-failure resolves to null;
// callers render placeholders. The API key (if set) is read per-call.
//
// Return shapes are deliberately unchanged (data-or-null for reads,
// {ok,status,detail} for writes). The only addition is a side-effect call to
// auth.report() so the Authorize chip can re-verify opportunistically: a 403
// with a key set means the key is bad; a 2xx from a *gated* write confirms it
// (a 2xx from a public read proves nothing — see auth.js).
import { getApiKey, report } from './auth.js';

async function getJson(path) {
  try {
    const headers = {};
    const key = getApiKey();
    if (key) headers['api_key'] = key;
    const r = await fetch(path, { cache: 'no-store', headers });
    if (key) report(r.status, false, key); // reads are public: only a 403 is meaningful here
    if (!r.ok) return null;
    return await r.json();
  } catch {
    return null;
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
    if (key) report(r.status, true, key); // writes are gated: a 2xx here confirms the key
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
    if (key) report(r.status, true, key);
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
  recentBlocks: (n = 10) => getJson(`/api/v1/blocks/recent?n=${n}`),
  difficultyHistory: (b = 60) => getJson(`/api/v1/difficulty/history?blocks=${b}`),
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
  },
};

export { getJson };
