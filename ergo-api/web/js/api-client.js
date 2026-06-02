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
};

export { getJson };
