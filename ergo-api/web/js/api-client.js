// Thin fetch wrapper. Any error/non-2xx/parse-failure resolves to null;
// callers render placeholders. The API key (if set) is read per-call.
import { getApiKey } from './settings.js';

async function getJson(path) {
  try {
    const headers = {};
    const key = getApiKey();
    if (key) headers['api_key'] = key;
    const r = await fetch(path, { cache: 'no-store', headers });
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
};

export { getJson };
