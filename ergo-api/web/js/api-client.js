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
    const r = await fetch(path, { cache: 'no-store', headers, signal: AbortSignal.timeout(12000) });
    if (key) report(r.status, false, key); // reads are public: only a 403 is meaningful here
    if (!r.ok) return null;
    return await r.json();
  } catch {
    return null;
  }
}

async function getAllPeerPages() {
  const items = [];
  let cursor = null;
  do {
    const query = cursor ? `?cursor=${encodeURIComponent(cursor)}` : '';
    const page = await getJson(`/api/v1/network/peers${query}`);
    if (!page || !Array.isArray(page.items) || !page.page) return null;
    items.push(...page.items);
    if (!page.page.has_more) return items;
    const next = page.page.next_cursor;
    if (!next || next === cursor) return items;
    cursor = next;
  } while (true);
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

async function nativeNode() {
  return getJson('/api/v1/node');
}

function normalizeNativeStatus(node) {
  if (!node?.status) return null;
  const status = { ...node.status };
  const header = node.tip?.best_header;
  const block = node.tip?.best_block;
  status.best_header_height = header?.height ?? null;
  status.best_full_block_height = block?.height ?? null;
  status.bootstrap = status.bootstrap_active ? {} : null;
  status.shadow = status.shadow_diverged ? { diverged: {} } : null;
  return status;
}

function normalizeNativeSync(node) {
  if (!node?.sync) return null;
  const sync = { ...node.sync };
  sync.best_header_height = sync.header_height;
  sync.best_full_block_height = sync.full_block_height;
  return sync;
}

function normalizeNativeIdentity(identity) {
  if (!identity) return null;
  return {
    ...identity,
    mode: identity.mode ?? `${identity.history_mode} · ${identity.state_backend}`,
    state_type: identity.state_type ?? identity.state_backend,
    mining: identity.mining ?? identity.mining_enabled,
    extra_index_enabled: identity.extra_index_enabled ?? identity.indexer_enabled,
    declared_addr: identity.declared_addr ?? identity.declared_address,
    bind_addr: identity.bind_addr ?? identity.bind_address,
  };
}

function normalizeNativeTip(node) {
  if (!node?.tip) return null;
  const tip = { ...node.tip };
  tip.best_full_block = tip.best_block;
  tip.headers_ahead_of_full_blocks =
    (tip.best_header?.height ?? 0) - (tip.best_block?.height ?? 0);
  return tip;
}

export const api = {
  node: nativeNode,
  status: async () => normalizeNativeStatus(await nativeNode()),
  info: () => getJson('/api/v1/node/info'),
  sync: async () => normalizeNativeSync(await nativeNode()),
  tip: async () => normalizeNativeTip(await nativeNode()),
  identity: async () => normalizeNativeIdentity(await getJson('/api/v1/node/identity')),
  host: () => getJson('/api/v1/node/host'),
  indexedHeight: () => getJson('/blockchain/indexedHeight'),
  // Operator health superset of indexedHeight (self-repair markers + totals).
  // 404s on indexer-less wiring — the UI reads null as "extra-index disabled".
  indexerStatus: () => getJson('/api/v1/indexer/status'),
  recentBlocks: (n = 10) => getJson(`/api/v1/chain/blocks/recent?n=${n}`),
  // Operator event feed (bounded ring tail). `since` = last-seen seq.
  events: (since = 0) => getJson(`/api/v1/node/events${since ? `?since=${since}` : ''}`),
  // Mining surface — routes mount only when mining is wired (404 = off).
  // candidate is cheap on repeat calls (same-tip template cache node-side).
  miningCandidate: () => getJson('/mining/candidate'),
  miningRewardAddress: () => getJson('/mining/rewardAddress'),
  miningRewardPublicKey: () => getJson('/mining/rewardPublicKey'),
  // Network mining landscape: last-`window` headers folded by miner pk,
  // addresses derived server-side. Rides the chain reader (404 = old node).
  minerStats: (window = 720) => getJson(`/api/v1/mining/minerStats?window=${window}`),
  // Emission schedule facts at a height ({minerReward, reemitted, …} nanoERG).
  emissionAt: (height) => getJson(`/emission/at/${height}`),
  difficultyHistory: (b = 60) => getJson(`/api/v1/difficulty/history?blocks=${b}`),
  // Mempool wait-time histogram: bins+1 buckets of {nTxns, totalFee}.
  poolHistogram: (bins = 10, maxtimeMs = 3_600_000) =>
    getJson(`/transactions/poolHistogram?bins=${bins}&maxtime=${maxtimeMs}`),
  peers: getAllPeerPages,
  mempoolSummary: () => getJson('/api/v1/mempool/summary'),
  mempoolTransactions: () => getJson('/api/v1/mempool/transactions'),
  txDetail: (id) => getJson(`/api/v1/transactions/${id}/detail`),
  votes: () => getJson('/api/v1/votes'),
  votesHistory: () => getJson('/api/v1/voting/history'),
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
