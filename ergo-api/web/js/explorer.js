// Explorer: global search + block / tx / box / address / token detail views
// over the node's own chain data (`/blocks/*`, ungated) and extra-index
// (`/blockchain/*`, 503-gated until the indexer is caught up).
//
// Deep-linkable sub-routes (see router.js): `#explorer` (home = omnibox +
// recent blocks), `#explorer/block/<headerId>`, `#explorer/tx/<id>`,
// `#explorer/box/<id>`, `#explorer/address/<addr>`, `#explorer/token/<id>`.
// Every entity view cross-links (tx → boxes → addresses → txs …) with plain
// anchors, so back/forward and copy-link work like a real explorer.
//
// Data-shape traps handled here (see the API notes in each view):
// - /blockchain/* paged routes default to limit=5 — every call passes an
//   explicit limit.
// - unspent/* returns a bare array; spent-inclusive byAddress/byTokenId
//   return {items,total} — two envelopes in one family.
// - 404 on /blockchain/* is ambiguous (malformed id == unknown id), and every
//   gated route 503s while the indexer syncs — the home banner + per-view
//   fallbacks keep that from presenting as "not found".
// - header.difficulty is a decimal STRING (may exceed 2^53) — displayed
//   verbatim, never via Number().
import { api, getJson } from './api-client.js';
import { makeTable, copyBtn } from './table.js';
import { erg, num, bytes, dur, truncMiddle } from './format.js';

let root = null;
let body = null;
let statusEl = null;
let input = null;
// Route + paint-race guard: each navigation bumps `seq`; async renders check
// they are still the current view before touching the DOM.
let seq = 0;
let tail = '';
// Cached /blockchain/indexedHeight body (always-200, carries status even
// while the gated routes 503) — drives the syncing/halted banner.
let idx = null;

const PAGE = 20;

// ---- tiny DOM helpers (data goes through textContent, never innerHTML) ----

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text != null) e.textContent = text;
  return e;
}

function link(path, label, cls) {
  const a = el('a', cls || 'ex-link', label);
  a.href = `#explorer/${path}`;
  return a;
}

// Truncated hash + copy button, optionally linking to an entity view.
function hashNode(id, path) {
  const w = el('span', 'ex-hash');
  w.append(path ? link(path, truncMiddle(id, 8, 8)) : el('span', 'v--hash', truncMiddle(id, 8, 8)), copyBtn(id));
  return w;
}

function kvRow(grid, label, valueNode) {
  grid.append(el('span', 'k', label));
  const v = el('span', 'v');
  if (valueNode instanceof Node) v.append(valueNode);
  else v.textContent = valueNode == null ? '—' : String(valueNode);
  grid.append(v);
}

function panel(title) {
  const p = el('section', 'panel ex-panel');
  const head = el('div', 'panel__head');
  // Real heading (not a span): gives screen-reader users jump targets and
  // focusView() an announcement anchor after cross-link navigation.
  head.append(el('h2', 'panel__title', title));
  const bodyEl = el('div', 'panel__body');
  p.append(head, bodyEl);
  return { panel: p, body: bodyEl, head };
}

// After a view swap, the element the user activated was destroyed with the
// old view, dropping focus to <body> with no announcement. Move it onto the
// fresh view's first heading — but never steal an active control (the
// omnibox after '/', a pager button mid-interaction, etc.).
function focusView() {
  if (document.activeElement !== document.body) return;
  const t = body.querySelector('.panel__title, .banner');
  if (t) {
    t.tabIndex = -1;
    t.focus({ preventScroll: true });
  }
}

function banner(kind, text) {
  return el('div', `banner banner--${kind}`, text);
}

function tsNode(unixMs) {
  if (!unixMs) return el('span', null, '—');
  const w = el('span');
  w.append(
    el('span', null, new Date(unixMs).toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC')),
    el('span', 'muted', ` · ${dur(Math.max(0, Math.floor((Date.now() - unixMs) / 1000)))} ago`),
  );
  return w;
}

function spentPill(spentTxId) {
  const p = el('span', spentTxId ? 'pill pill--warn' : 'pill pill--ok', spentTxId ? 'spent' : 'unspent');
  return p;
}

// Token amounts arrive as bare JSON numbers (u64 on the wire) — anything past
// 2^53 already lost precision at JSON.parse. Flag it instead of silently
// rounding. (Emitting u64 as strings server-side, as difficulty already is,
// is the real fix — tracked as a follow-up since it changes the API contract.)
function amt(v) {
  if (v == null) return '—';
  return Number.isSafeInteger(v) ? num(v) : `≈${num(v)}`;
}

function go(path) {
  location.hash = path ? `explorer/${path}` : 'explorer';
}

// ---- indexer availability (drives banners + search degradation) ----

// True once the FIRST indexedHeight read has completed (success or failure):
// distinguishes "not yet fetched" from "fetch failed / no indexer" so a cold
// load can't flash the alarming unavailable-banner on a healthy node.
let idxLoaded = false;

async function refreshIndexerStatus() {
  idx = await api.indexedHeight();
  idxLoaded = true;
}

function indexerReady() {
  return idx?.status === 'caughtUp';
}

function indexerBanner() {
  if (!idx) return banner('warn', 'Extra-index unavailable — box / address / token views are limited to chain data.');
  if (idx.status === 'halted') {
    return banner('err', `Extra-index halted (${idx.haltReason || 'unknown'}) — box / address / token lookups unavailable.`);
  }
  return banner(
    'info',
    `Extra-index syncing (${num(idx.indexedHeight)} / ${num(idx.fullHeight)}) — box / address / token lookups come online when it catches up.`,
  );
}

// Honest reason a gated (box / token / rich-tx / address) lookup came back
// empty. null means "the index is caught up, so this is a genuine not-found";
// otherwise it names WHY the extra-index couldn't answer (unavailable /
// halted / still syncing) so an empty result never masquerades as "absent".
function gatedMiss() {
  if (indexerReady()) return null;
  if (!idx) return 'extra-index unavailable';
  if (idx.status === 'halted') return `extra-index halted (${idx.haltReason || 'unknown'})`;
  return 'extra-index still syncing';
}

// ---- search ----

const HEX64 = /^[0-9a-fA-F]{64}$/;
// Base58 (Bitcoin alphabet) — the char class EXCLUDES '/' and '.', which is
// what actually closes the path-traversal hole; the length bounds are only a
// sanity cap and err WIDE on both ends. Real mainnet extremes: the trueProp
// burn address `4MQyML64GnzMxZgm` is 16 chars (a 20-char floor made it
// unsearchable and its cross-links dead), and P2S scripts encode arbitrary
// ErgoTrees far beyond a 51-char P2PK. encodeURIComponent keeps any length
// safe in a fetch path, so tight caps buy no security — only lost coverage.
const BASE58 = /^[1-9A-HJ-NP-Za-km-z]{9,4096}$/;

// Search epoch: a slow earlier probe must not call go() / overwrite status
// after a newer search was issued OR after the user navigated away. Each
// runSearch bumps `searchSeq`; every post-await step re-checks both it and the
// route `seq`.
let searchSeq = 0;

async function runSearch(q) {
  const query = q.trim();
  if (!query) return;
  const mine = ++searchSeq;
  const myRoute = seq;
  const stale = () => mine !== searchSeq || myRoute !== seq;
  setStatus('searching…');

  // Height: digits only → canonical header id at that height (index 0 is the
  // best-chain id when a forked height returns several).
  if (/^\d+$/.test(query)) {
    const ids = await getJson(`/blocks/at/${query}`);
    if (stale()) return;
    if (Array.isArray(ids) && ids.length) {
      setStatus('');
      go(`block/${ids[0]}`);
    } else {
      setStatus(`no block at height ${num(Number(query))}`);
    }
    return;
  }

  // 64-hex: could be a block, tx, box, or token id — probe all four in
  // parallel and route by precedence (the id domains don't collide in
  // practice). The tx probe uses the ungated detail route so mempool txs and
  // syncing-indexer nodes still resolve.
  if (HEX64.test(query)) {
    const id = query.toLowerCase();
    const [blk, tx, pooled, box, token] = await Promise.all([
      getJson(`/blocks/${id}/header`),
      getJson(`/api/v1/transactions/${id}/detail`),
      // Mempool-only probe: the slim detail route above mounts only when an
      // indexer is plumbed, so this keeps mempool txs searchable on
      // indexer-less nodes too.
      getJson(`/transactions/unconfirmed/byTransactionId/${id}`),
      indexerReady() ? getJson(`/blockchain/box/byId/${id}`) : null,
      indexerReady() ? getJson(`/blockchain/token/byId/${id}`) : null,
    ]);
    if (stale()) return;
    setStatus('');
    if (blk) return go(`block/${id}`);
    if (tx || pooled) return go(`tx/${id}`);
    if (box) return go(`box/${id}`);
    if (token) return go(`token/${id}`);
    setStatus(indexerReady() ? 'no block, transaction, box, or token with that id' : `not found — searched blocks + mempool only (${gatedMiss()})`);
    return;
  }

  // Address: any base58-decodable address is a "hit" (the chain has no
  // existence probe — unknown addresses legitimately show a zero balance).
  if (BASE58.test(query)) {
    const bal = await getJson(`/blockchain/balanceForAddress/${encodeURIComponent(query)}`);
    if (stale()) return;
    if (bal) {
      setStatus('');
      go(`address/${query}`);
    } else {
      setStatus(indexerReady() ? 'not a valid address for this network' : `address lookups unavailable — ${gatedMiss()}`);
    }
    return;
  }

  setStatus('enter a height, block / tx / box / token id, or address');
}

function setStatus(text) {
  if (statusEl) statusEl.textContent = text;
}

export function focusSearch() {
  if (input) {
    input.focus();
    input.select();
  }
}

// ---- views ----

function loading() {
  body.replaceChildren(el('div', 'muted', 'loading…'));
}

function notFound(what, extra) {
  body.replaceChildren();
  body.append(banner('warn', `${what} not found${extra ? ` — ${extra}` : ''}`));
  const back = link('', '← back to explorer');
  back.href = '#explorer';
  body.append(back);
  focusView();
}

// A gated (box / token / rich-tx / address) lookup came back empty. The cached
// `idx` may be stale — the index could have fallen behind and 503'd this very
// request since our last status read — so refresh before deciding whether this
// is a GENUINE not-found (index caught up) or a degraded one (unavailable /
// halted / syncing). Re-checks the route seq across its own await.
async function notFoundGated(what, mySeq, readyMsg) {
  await refreshIndexerStatus();
  if (mySeq !== seq) return;
  notFound(what, indexerReady() ? readyMsg || null : gatedMiss());
}

// ---- shared pager ----

// prev/next pager row. `total` null = bare-array mode (end detected by a short
// page). `onMove(newOffset)` re-fetches. Buttons carry data-pg so callers can
// restore keyboard focus across rebuilds (the pager is replaced per page).
function pagerEl(offset, total, got, onMove) {
  const w = el('div', 'ex-pager');
  const prev = el('button', 'btn btn--ghost btn--sm', '← prev');
  prev.type = 'button';
  prev.dataset.pg = 'prev';
  prev.disabled = offset === 0;
  prev.onclick = () => onMove(Math.max(0, offset - PAGE));
  const label = el(
    'span',
    'muted',
    got === 0
      ? total != null
        ? `0 of ${num(total)}`
        : 'no results'
      : total != null
        ? `${num(offset + 1)}–${num(offset + got)} of ${num(total)}`
        : `${num(offset + 1)}–${num(offset + got)}`,
  );
  const next = el('button', 'btn btn--ghost btn--sm', 'next →');
  next.type = 'button';
  next.dataset.pg = 'next';
  // got === 0 also disables next: an empty page IS the end — prevents paging
  // past a final page that was exactly full into a "21–20" ghost page.
  next.disabled = got === 0 || (total != null ? offset + PAGE >= total : got < PAGE);
  next.onclick = () => onMove(offset + PAGE);
  w.append(prev, label, next);
  return w;
}

// Restore keyboard focus onto the rebuilt pager: the button the user pressed
// was destroyed with the old page (focus fell to <body>, stranding keyboard
// users). Falls back to the sibling when the pressed button became disabled.
function refocusPager(host, pg) {
  if (!pg) return;
  const want = host.querySelector(`[data-pg="${pg}"]`);
  const alt = host.querySelector(`[data-pg="${pg === 'prev' ? 'next' : 'prev'}"]`);
  const target = want && !want.disabled ? want : alt && !alt.disabled ? alt : null;
  if (target) target.focus();
}

// Home view: a persisted table + banner slot so the 4s onSlow refresh can
// update rows in place WITHOUT rebuilding the table (which would reset the
// user's chosen column sort).
let homeTable = null;
let homeHost = null;
let homeBannerSlot = null;

function refreshHomeBanner() {
  if (!homeBannerSlot) return;
  homeBannerSlot.replaceChildren();
  // First status read still in flight → suppress; the mount().then re-route
  // paints the real state moments later without a scary transient.
  if (!idxLoaded && !idx) return;
  if (!indexerReady()) homeBannerSlot.append(indexerBanner());
}

// Home: recent blocks + (when relevant) the indexer-status banner.
async function renderHome(mySeq) {
  // Entity → home: blank the outgoing view immediately so its controls can't
  // absorb clicks while recent-blocks loads (zombie-interaction guard). Skip
  // when the home table is already painted to avoid flashing "loading…" over
  // it on banner-driven re-routes.
  if (!homeHost?.isConnected) loading();
  const recent = await api.recentBlocks(32);
  if (mySeq !== seq) return;
  body.replaceChildren();
  homeBannerSlot = el('div');
  refreshHomeBanner();
  body.append(homeBannerSlot);
  const { panel: p, body: pb } = panel('Recent blocks');
  homeHost = el('div');
  pb.append(homeHost);
  homeTable = makeTable(
    homeHost,
    [
      {
        key: 'height',
        label: 'Height',
        width: 90,
        render: (b) => link(`block/${b.header_id}`, num(b.height)),
        sort: (b) => b.height,
      },
      { key: 'age', label: 'Age', width: 80, align: 'right', render: (b) => dur(Math.max(0, Math.floor((Date.now() - b.ts_unix_ms) / 1000))), sort: (b) => -b.ts_unix_ms },
      { key: 'txs', label: 'Txs', width: 60, align: 'right', sort: (b) => b.txs },
      { key: 'size', label: 'Size', width: 80, align: 'right', render: (b) => bytes(b.size_bytes), sort: (b) => b.size_bytes },
      { key: 'id', label: 'Block ID', render: (b) => hashNode(b.header_id, `block/${b.header_id}`), sort: (b) => b.header_id },
    ],
    { rowKey: (b) => b.header_id, initialSort: { key: 'height', dir: -1 } },
  );
  homeTable.update(Array.isArray(recent) ? recent : []);
  body.append(p);
}

// Block: full block from the (ungated) chain route — works while the indexer
// syncs. Height search canonicalizes to a header id before landing here.
async function renderBlock(id, mySeq) {
  loading();
  let blk = await getJson(`/blocks/${id}`);
  if (mySeq !== seq) return;
  let headerOnly = false;
  if (!blk?.header) {
    // Header-first sync: the header chain runs ahead of block bodies, so
    // /blocks/:id 404s while /blocks/at/:h (and header search) already
    // resolve this id. Fall back to the header route and say so honestly
    // instead of a misleading "block not found".
    const hdr = await getJson(`/blocks/${id}/header`);
    if (mySeq !== seq) return;
    if (!hdr) return notFound('block');
    blk = { header: hdr, size: null, blockTransactions: null };
    headerOnly = true;
  }
  const h = blk.header;
  body.replaceChildren();
  if (headerOnly) {
    body.append(banner('info', 'header only — the block body has not been downloaded yet (node still syncing)'));
  }

  const { panel: p, body: pb, head } = panel(`Block ${num(h.height)}`);
  // prev / next chain navigation: parent is direct; next resolves via the
  // canonical id at height+1 (absent at the tip).
  const nav = el('span', 'ex-nav');
  const prev = link(`block/${h.parentId}`, '← parent');
  nav.append(prev);
  const next = el('a', 'ex-link', 'next →');
  next.href = '#';
  next.onclick = async (e) => {
    e.preventDefault();
    const ids = await getJson(`/blocks/at/${h.height + 1}`);
    // The resolve is async — if the user navigated away meanwhile, don't yank
    // them to the next block.
    if (mySeq !== seq) return;
    if (Array.isArray(ids) && ids.length) go(`block/${ids[0]}`);
    else setStatus('already at the chain tip');
  };
  nav.append(next);
  head.append(nav);

  const grid = el('div', 'kv');
  kvRow(grid, 'id', hashNode(h.id));
  kvRow(grid, 'time', tsNode(h.timestamp));
  kvRow(grid, 'size', bytes(blk.size));
  kvRow(grid, 'version', String(h.version));
  // difficulty is a decimal string that can exceed 2^53 — show verbatim.
  kvRow(grid, 'difficulty', h.difficulty);
  kvRow(grid, 'votes', h.votes || '—');
  kvRow(grid, 'miner pk', h.powSolutions?.pk ? hashNode(h.powSolutions.pk) : '—');
  kvRow(grid, 'state root', h.stateRoot ? hashNode(h.stateRoot) : '—');
  pb.append(grid);
  body.append(p);

  if (headerOnly) return; // no body yet — the banner above explains why

  const txs = blk.blockTransactions?.transactions || [];
  const { panel: tp, body: tpb } = panel(`Transactions · ${txs.length}`);
  const host = el('div');
  tpb.append(host);
  makeTable(
    host,
    [
      { key: 'i', label: '#', width: 40, align: 'right', render: (t) => String(t._i), sort: (t) => t._i },
      { key: 'id', label: 'TX ID', render: (t) => hashNode(t.id, `tx/${t.id}`), sort: (t) => t.id },
      { key: 'io', label: 'In/Out', width: 70, align: 'right', render: (t) => `${(t.inputs || []).length}/${(t.outputs || []).length}`, sort: (t) => (t.inputs || []).length },
      { key: 'size', label: 'Size', width: 80, align: 'right', render: (t) => bytes(t.size), sort: (t) => t.size },
    ],
    { rowKey: (t) => t.id, initialSort: { key: 'i', dir: 1 } },
  ).update(txs.map((t, i) => ({ ...t, _i: i })));
  body.append(tp);
}

// One input/output row shared by the confirmed and unconfirmed tx views.
// Accepts either the rich IndexedErgoBoxResponse (boxId/address/value/assets)
// or the slim ApiIoBox (box_id/address/value/tokens, nullable when a pool
// input can't be resolved).
function ioLine(b) {
  const row = el('div', 'ex-io');
  const boxId = b.boxId || b.box_id;
  const tokens = b.assets || b.tokens || [];
  row.append(boxId ? hashNode(boxId, `box/${boxId}`) : el('span', 'muted', '(unresolved)'));
  const addr = el('span', 'ex-io__addr');
  if (b.address) addr.append(link(`address/${b.address}`, truncMiddle(b.address, 10, 8)));
  else addr.append(el('span', 'muted', '—'));
  row.append(addr);
  const val = el('span', 'ex-io__val', b.value != null ? `${erg(b.value)} ERG` : '—');
  row.append(val);
  if (tokens.length) {
    const tk = el('div', 'ex-io__tokens');
    for (const t of tokens) {
      const tid = t.tokenId || t.token_id;
      const line = el('div', 'muted');
      line.append('+ ', el('span', null, amt(t.amount)), ' ', link(`token/${tid}`, truncMiddle(tid, 6, 6)));
      tk.append(line);
    }
    row.append(tk);
  }
  return row;
}

async function renderTx(id, mySeq) {
  loading();
  // Status is derived ONLY from source-authoritative endpoints, never from the
  // source-hiding slim /detail route (which searches the index *then* the
  // mempool and hides which it hit — so its mere presence can't prove
  // confirmed vs pending):
  //   • rich  = /blockchain/transaction/byId — CONFIRMED-only (carries blockId)
  //   • pool  = /transactions/unconfirmed/byTransactionId — MEMPOOL-only
  //   • slim  = /api/v1/transactions/:id/detail — used ONLY to render IO, and
  //             only in the degraded case where rich 503s behind a syncing
  //             index; by then `pool` has authoritatively ruled out mempool.
  // Residual: during the ~1-block mempool→index turnover a tx can momentarily
  // satisfy both rich-null and pool; it then reads "unconfirmed" until the
  // index ingests the block (rich resolves → confirmed). That flip is inherent
  // to any multi-read explorer and self-corrects on the next refresh.
  const rich = await getJson(`/blockchain/transaction/byId/${id}`);
  let pool = null;
  let slim = null;
  if (!rich) {
    [pool, slim] = await Promise.all([
      getJson(`/transactions/unconfirmed/byTransactionId/${id}`),
      getJson(`/api/v1/transactions/${id}/detail`),
    ]);
  }
  if (mySeq !== seq) return;
  if (!rich && !pool && !slim) return notFoundGated('transaction', mySeq);
  body.replaceChildren();

  const { panel: p, body: pb } = panel('Transaction');
  const grid = el('div', 'kv');
  kvRow(grid, 'id', hashNode(id));
  if (rich) {
    kvRow(grid, 'block', hashNode(rich.blockId, `block/${rich.blockId}`));
    kvRow(grid, 'height', num(rich.inclusionHeight));
    // numConfirmations = fullHeight − inclusionHeight, so the tip block reads
    // 0 — annotate it so "0" can't be misread as unconfirmed.
    kvRow(grid, 'confirmations', rich.numConfirmations === 0 ? '0 · in latest block' : num(rich.numConfirmations));
    kvRow(grid, 'time', tsNode(rich.timestamp));
    kvRow(grid, 'size', bytes(rich.size));
    kvRow(grid, 'index in block', String(rich.index));
  } else if (pool || indexerReady()) {
    // pool → authoritatively in the mempool. OR: the index is caught up yet the
    // confirmed-only rich route missed while slim resolved → slim served it from
    // the mempool (it searches the index first), so it's pending too. (This also
    // covers a pool probe that failed rather than 404'd — getJson collapses both
    // to null — without mislabelling a mempool tx as confirmed on a healthy node.)
    kvRow(grid, 'status', el('span', 'pill pill--warn', 'unconfirmed'));
  } else {
    // Index is BEHIND (rich 503'd) and pool ruled out mempool: slim is our only
    // source. Best-effort "confirmed", flagged as detail-limited — naming the
    // real degradation (syncing vs halted vs unavailable), not assuming syncing.
    const s = el('span');
    s.append(el('span', 'pill pill--ok', 'confirmed'), el('span', 'muted', ` · ${gatedMiss()} — limited detail`));
    kvRow(grid, 'status', s);
  }
  pb.append(grid);
  body.append(p);

  // IO source: rich is complete. For an unconfirmed tx MERGE the two partial
  // sources instead of picking one: slim resolves input/output address+value+
  // tokens but its outputs carry box_id null (the server builds them from
  // candidates), while the pool tx authoritatively carries every output boxId
  // plus the dataInputs slim lacks. Zip by index — both are the tx's ordered
  // IO lists.
  let io = rich;
  if (!io && slim && pool) {
    io = {
      inputs: (slim.inputs || []).map((inp, i) => ({ ...inp, box_id: inp.box_id ?? pool.inputs?.[i]?.boxId })),
      outputs: (slim.outputs || []).map((out, i) => ({ ...out, box_id: out.box_id ?? pool.outputs?.[i]?.boxId })),
      dataInputs: pool.dataInputs || [],
    };
  }
  if (!io) io = slim || pool;
  const inputs = io.inputs || [];
  const outputs = io.outputs || [];
  const grid2 = el('div', 'ex-iogrid');
  const colOf = (title, items) => {
    const { panel: cp, body: cb } = panel(`${title} · ${items.length}`);
    for (const it of items) cb.append(ioLine(it));
    if (!items.length) cb.append(el('div', 'muted', 'none'));
    return cp;
  };
  grid2.append(colOf('Inputs', inputs), colOf('Outputs', outputs));
  body.append(grid2);

  const dataInputs = io.dataInputs || [];
  if (dataInputs.length) {
    const { panel: dp, body: db } = panel(`Data inputs · ${dataInputs.length}`);
    for (const d of dataInputs) {
      const bid = d.boxId || d.box_id;
      db.append(bid ? hashNode(bid, `box/${bid}`) : el('span', 'muted', '(unresolved)'));
    }
    body.append(dp);
  }
}

async function renderBox(id, mySeq) {
  loading();
  const b = await getJson(`/blockchain/box/byId/${id}`);
  if (mySeq !== seq) return;
  if (!b) return notFoundGated('box', mySeq);
  body.replaceChildren();

  const { panel: p, body: pb, head } = panel('Box');
  head.append(spentPill(b.spentTransactionId));
  const grid = el('div', 'kv');
  kvRow(grid, 'id', hashNode(b.boxId));
  kvRow(grid, 'value', `${erg(b.value)} ERG`);
  kvRow(grid, 'address', b.address ? link(`address/${b.address}`, truncMiddle(b.address, 12, 10)) : '—');
  const created = el('span');
  created.append(hashNode(b.transactionId, `tx/${b.transactionId}`), el('span', 'muted', ` at ${num(b.inclusionHeight)}`));
  kvRow(grid, 'created by', created);
  if (b.spentTransactionId) kvRow(grid, 'spent by', hashNode(b.spentTransactionId, `tx/${b.spentTransactionId}`));
  kvRow(grid, 'creation height', num(b.creationHeight));
  kvRow(grid, 'global index', num(b.globalIndex));
  pb.append(grid);
  body.append(p);

  if (Array.isArray(b.assets) && b.assets.length) {
    const { panel: ap, body: ab } = panel(`Tokens · ${b.assets.length}`);
    for (const a of b.assets) {
      const row = el('div', 'ex-io');
      row.append(hashNode(a.tokenId, `token/${a.tokenId}`), el('span', 'ex-io__val', amt(a.amount)));
      ab.append(row);
    }
    body.append(ap);
  }

  const regs = b.additionalRegisters || {};
  const regKeys = Object.keys(regs).sort();
  if (regKeys.length) {
    const { panel: rp, body: rb } = panel(`Registers · ${regKeys.length}`);
    const grid3 = el('div', 'kv');
    for (const k of regKeys) {
      const v = el('span', 'ex-hash');
      v.append(el('code', 'ex-reg', truncMiddle(regs[k], 18, 12)), copyBtn(regs[k]));
      kvRow(grid3, k, v);
    }
    rb.append(grid3);
    body.append(rp);
  }
}

// Address: balance + paged txs / unspent boxes tabs. The unspent route
// returns a bare array (no total) → its pager is prev/next only.
async function renderAddress(addr, mySeq) {
  loading();
  const bal = await getJson(`/blockchain/balanceForAddress/${encodeURIComponent(addr)}`);
  if (mySeq !== seq) return;
  if (!bal) return notFoundGated('address', mySeq, 'invalid for this network');
  body.replaceChildren();

  const { panel: p, body: pb } = panel('Address');
  const grid = el('div', 'kv');
  kvRow(grid, 'address', hashNode(addr));
  kvRow(grid, 'confirmed', `${erg(bal.confirmed?.nanoErgs)} ERG`);
  const tokens = bal.confirmed?.tokens || [];
  kvRow(grid, 'tokens', tokens.length ? `${tokens.length} kind${tokens.length > 1 ? 's' : ''}` : 'none');
  // The unconfirmed figure is strictly additive (incoming only) — pending
  // outgoing spends do NOT reduce it, so it is labelled as incoming.
  const un = bal.unconfirmed?.nanoErgs;
  if (un) kvRow(grid, 'unconfirmed in', `+${erg(un)} ERG`);
  pb.append(grid);
  body.append(p);

  if (tokens.length) {
    const { panel: tp, body: tb } = panel('Token balances');
    for (const t of tokens) {
      const row = el('div', 'ex-io');
      row.append(hashNode(t.tokenId, `token/${t.tokenId}`), el('span', 'ex-io__val', amt(t.amount)));
      tb.append(row);
    }
    body.append(tp);
  }

  // Tabs: transactions (has {items,total}) / unspent boxes (bare array).
  const tabs = el('div', 'tabs');
  tabs.setAttribute('role', 'tablist');
  const txTab = el('button', 'tab', 'Transactions');
  const boxTab = el('button', 'tab', 'Unspent boxes');
  txTab.type = 'button';
  boxTab.type = 'button';
  txTab.setAttribute('role', 'tab');
  boxTab.setAttribute('role', 'tab');
  tabs.append(txTab, boxTab);
  body.append(tabs);
  const tabHost = el('div');
  body.append(tabHost);

  let mode = 'txs';
  let offset = 0;
  // Local epoch: every page() bumps it, so an in-flight tab/pager fetch that is
  // superseded by a newer one within THIS address view bails instead of
  // stale-painting. (The route `seq` guard only covers navigating away.)
  let pageEpoch = 0;
  const select = (m) => {
    mode = m;
    offset = 0;
    txTab.setAttribute('aria-selected', String(m === 'txs'));
    boxTab.setAttribute('aria-selected', String(m === 'boxes'));
    page();
  };
  txTab.onclick = () => select('txs');
  boxTab.onclick = () => select('boxes');

  const move = (o) => {
    offset = o;
    page();
  };

  async function page() {
    const myRoute = seq;
    const myPage = ++pageEpoch;
    const stale = () => myRoute !== seq || myPage !== pageEpoch;
    // Which pager button (if any) held focus — restored after the rebuild so
    // keyboard users aren't dumped to <body> on every page.
    const focusPg = document.activeElement?.dataset?.pg || null;
    tabHost.replaceChildren(el('div', 'muted', 'loading…'));
    if (mode === 'txs') {
      const r = await getJson(`/blockchain/transaction/byAddress/${encodeURIComponent(addr)}?offset=${offset}&limit=${PAGE}`);
      if (stale()) return;
      tabHost.replaceChildren();
      const items = r?.items || [];
      const host = el('div');
      tabHost.append(host);
      makeTable(
        host,
        [
          { key: 'id', label: 'TX ID', render: (t) => hashNode(t.id, `tx/${t.id}`), sort: (t) => t.id },
          { key: 'height', label: 'Height', width: 90, align: 'right', render: (t) => num(t.inclusionHeight), sort: (t) => t.inclusionHeight },
          { key: 'time', label: 'Age', width: 90, align: 'right', render: (t) => dur(Math.max(0, Math.floor((Date.now() - t.timestamp) / 1000))), sort: (t) => -t.timestamp },
          { key: 'size', label: 'Size', width: 80, align: 'right', render: (t) => bytes(t.size), sort: (t) => t.size },
        ],
        { rowKey: (t) => t.id, initialSort: { key: 'height', dir: -1 } },
      ).update(items);
      tabHost.append(pagerEl(offset, r?.total ?? null, items.length, move));
      refocusPager(tabHost, focusPg);
    } else {
      const items = await getJson(
        `/blockchain/box/unspent/byAddress/${encodeURIComponent(addr)}?offset=${offset}&limit=${PAGE}&sortDirection=desc`,
      );
      if (stale()) return;
      tabHost.replaceChildren();
      const rows = Array.isArray(items) ? items : [];
      const host = el('div');
      tabHost.append(host);
      makeTable(
        host,
        [
          { key: 'id', label: 'Box ID', render: (b) => hashNode(b.boxId, `box/${b.boxId}`), sort: (b) => b.boxId },
          { key: 'value', label: 'Value ERG', width: 130, align: 'right', render: (b) => erg(b.value), sort: (b) => b.value },
          { key: 'tokens', label: 'Tokens', width: 70, align: 'right', render: (b) => String((b.assets || []).length), sort: (b) => (b.assets || []).length },
          { key: 'height', label: 'Created', width: 90, align: 'right', render: (b) => num(b.inclusionHeight), sort: (b) => b.inclusionHeight },
        ],
        { rowKey: (b) => b.boxId, initialSort: { key: 'height', dir: -1 } },
      ).update(rows);
      tabHost.append(pagerEl(offset, null, rows.length, move));
      refocusPager(tabHost, focusPg);
    }
  }

  select('txs');
}

async function renderToken(id, mySeq) {
  loading();
  const t = await getJson(`/blockchain/token/byId/${id}`);
  if (mySeq !== seq) return;
  if (!t) return notFoundGated('token', mySeq);
  body.replaceChildren();

  const { panel: p, body: pb } = panel(t.name ? `Token · ${t.name}` : 'Token');
  const grid = el('div', 'kv');
  kvRow(grid, 'id', hashNode(t.id));
  kvRow(grid, 'name', t.name || '—');
  kvRow(grid, 'description', t.description || '—');
  kvRow(grid, 'decimals', String(t.decimals ?? 0));
  kvRow(grid, 'emission', amt(t.emissionAmount));
  kvRow(grid, 'minted in box', hashNode(t.boxId, `box/${t.boxId}`));
  pb.append(grid);
  body.append(p);

  // Holding boxes: paged ({items,total} envelope) with the shared pager —
  // previously only the first 20 rendered while the title advertised a total
  // the user could never reach.
  const boxSection = el('div');
  body.append(boxSection);
  let offset = 0;
  let pageEpoch = 0;
  async function pageBoxes() {
    const myPage = ++pageEpoch;
    const focusPg = document.activeElement?.dataset?.pg || null;
    const r = await getJson(`/blockchain/box/byTokenId/${id}?offset=${offset}&limit=${PAGE}`);
    if (mySeq !== seq || myPage !== pageEpoch) return;
    const items = r?.items || [];
    const { panel: bp, body: bb } = panel(`Boxes holding it${r?.total != null ? ` · ${num(r.total)}` : ''}`);
    const host = el('div');
    bb.append(host);
    makeTable(
      host,
      [
        { key: 'id', label: 'Box ID', render: (b) => hashNode(b.boxId, `box/${b.boxId}`), sort: (b) => b.boxId },
        {
          key: 'amount',
          label: 'Amount',
          width: 120,
          align: 'right',
          render: (b) => amt((b.assets || []).find((a) => a.tokenId === id)?.amount),
          sort: (b) => Number((b.assets || []).find((a) => a.tokenId === id)?.amount ?? 0),
        },
        { key: 'state', label: 'State', width: 90, render: (b) => spentPill(b.spentTransactionId), sort: (b) => (b.spentTransactionId ? 1 : 0) },
        { key: 'height', label: 'Created', width: 90, align: 'right', render: (b) => num(b.inclusionHeight), sort: (b) => b.inclusionHeight },
      ],
      { rowKey: (b) => b.boxId, initialSort: { key: 'height', dir: -1 } },
    ).update(items);
    bb.append(
      pagerEl(offset, r?.total ?? null, items.length, (o) => {
        offset = o;
        pageBoxes();
      }),
    );
    boxSection.replaceChildren(bp);
    refocusPager(boxSection, focusPg);
  }
  await pageBoxes();
}

// ---- routing ----

function route() {
  const my = ++seq;
  setStatus('');
  const slash = tail.indexOf('/');
  const kind = slash < 0 ? tail : tail.slice(0, slash);
  const arg = slash < 0 ? '' : tail.slice(slash + 1);
  if (!kind) return renderHome(my);
  // SECURITY: validate the entity id against a strict shape BEFORE it can reach
  // a fetch URL. hex64 / base58 contain no '/' or '.', so this closes the
  // path-traversal hole where a crafted hash (e.g. `#explorer/block/../wallet/
  // lock`) would otherwise normalize to an api-key'd, state-changing wallet GET.
  // `focused` moves screen-reader/keyboard context onto the fresh view's
  // heading once the render lands (no-op if a newer route superseded it or
  // if the user is mid-interaction with a live control).
  const focused = (p) =>
    p.then(() => {
      if (my === seq) focusView();
    });
  if (kind === 'block' && HEX64.test(arg)) return focused(renderBlock(arg.toLowerCase(), my));
  if (kind === 'tx' && HEX64.test(arg)) return focused(renderTx(arg.toLowerCase(), my));
  if (kind === 'box' && HEX64.test(arg)) return focused(renderBox(arg.toLowerCase(), my));
  if (kind === 'token' && HEX64.test(arg)) return focused(renderToken(arg.toLowerCase(), my));
  if (kind === 'address' && BASE58.test(arg)) return focused(renderAddress(arg, my));
  // Anything else (unknown kind, malformed id, path-traversal attempt) → home
  // with an honest note; never fetch an unvalidated segment.
  setStatus('invalid or unsupported explorer link');
  return renderHome(my);
}

// ---- lifecycle ----

export function mount(el2) {
  root = el2;
  root.innerHTML = `
    <div class="pg-head">
      <div>
        <h1 class="pg-title">Explorer</h1>
        <span class="pg-count micro-label">chain + extra-index lookup</span>
      </div>
    </div>
    <form class="ex-omni" data-omni>
      <input class="input ex-omni__input" type="search" spellcheck="false" autocomplete="off"
             placeholder="height · block / tx / box / token id · address    ( / to focus )" aria-label="search the chain" />
      <button class="btn btn--primary" type="submit">Search</button>
    </form>
    <div class="ex-status micro-label" data-status role="status" aria-live="polite"></div>
    <div class="ex-body" data-body></div>`;
  body = root.querySelector('[data-body]');
  statusEl = root.querySelector('[data-status]');
  const form = root.querySelector('[data-omni]');
  input = form.querySelector('input');
  form.onsubmit = (e) => {
    e.preventDefault();
    runSearch(input.value);
  };
  refreshIndexerStatus().then(() => {
    // First paint may have rendered the home view before the status arrived —
    // refresh the banner slot IN PLACE. (A full route() here would bump seq
    // and silently cancel a search submitted during the round-trip; and if
    // home hasn't painted yet, renderHome refreshes the banner itself.)
    if (!tail) refreshHomeBanner();
  });
}

export function onRoute(t) {
  tail = t || '';
  route();
}

export function onShow() {
  refreshIndexerStatus();
}

// Leaving the section (app.js calls this on the outgoing renderer). Bump both
// guards so any in-flight render or search bails instead of painting into — or
// navigating back to — a section the user has left. `seq` alone wouldn't cover
// this: it only advances on Explorer's own onRoute, not on a cross-section switch.
export function onHide() {
  seq++;
  searchSeq++;
}

export async function onSlow() {
  // Snapshot the route seq: `tail` alone can't tell THIS home paint from a
  // replacement one (an entity detour and back returns tail to '' but bumps
  // seq twice) — without this, a slow tick could stale-paint old rows over a
  // fresh home render.
  const mySeq = seq;
  await refreshIndexerStatus();
  // Entity views are immutable snapshots — not auto-refreshed (a reload is one
  // hash click away). Only the home list ticks.
  if (tail || mySeq !== seq) return;
  const recent = await api.recentBlocks(32);
  if (tail || mySeq !== seq) return;
  if (homeTable && homeHost?.isConnected) {
    // In-place refresh: keeps the user's chosen column sort (a full renderHome
    // would rebuild the table and snap it back to the default).
    refreshHomeBanner();
    homeTable.update(Array.isArray(recent) ? recent : []);
  }
  // No fallback render: if the table isn't mounted here, a route()-driven
  // renderHome is in flight for this same seq — rendering again would race it
  // (two same-seq paints, last responder wins). The next tick refreshes.
}
