import { test } from 'node:test';
import assert from 'node:assert/strict';

// Execute the shipped explorer against inert elements and canned responses.
// These tests check search/view messages and routing, not browser layout.
class Element {
  children = [];
  textContent = '';
  value = '';
  dataset = {};
  nodes = new Map();

  querySelector(selector) {
    if (!this.nodes.has(selector)) this.nodes.set(selector, new Element());
    return this.nodes.get(selector);
  }
  replaceChildren(...nodes) { this.children = nodes; }
  append(...nodes) { this.children.push(...nodes); }
  focus() {}
}

globalThis.location = { search: '', hash: '' };
globalThis.sessionStorage = { getItem: () => null, setItem() {}, removeItem() {} };
globalThis.document = { createElement: () => new Element(), body: null, activeElement: null };

// path -> [status, body], or a list answering successive reads (last repeats).
let routes = new Map();
globalThis.fetch = async (path) => {
  let answer = routes.get(path) ?? [404, { reason: 'not-found' }];
  if (Array.isArray(answer[0])) answer = answer.length > 1 ? answer.shift() : answer[0];
  const [status, data] = answer;
  return { status, ok: status >= 200 && status < 300, json: async () => data, clone() { return this; } };
};

const explorer = await import('../js/explorer.js');
const root = new Element();
explorer.mount(root);
const status = () => root.querySelector('[data-status]').textContent;
const banner = () => root.querySelector('[data-body]').children[0]?.textContent;
const settle = () => new Promise((resolve) => setTimeout(resolve, 20));

const ID = 'ab'.repeat(32);
const ADDRESS = '9fRAWhdxEsTcdb8PhGNrZfwqa65zfkuYHAMmkQLcic1gdLSV5vA';
const BALANCE = `/blockchain/balanceForAddress/${ADDRESS}`;
const CAUGHT_UP = [200, { status: 'caughtUp', indexedHeight: 10, fullHeight: 10 }];
const SYNCING = [200, { status: 'syncing', indexedHeight: 5, fullHeight: 10 }];
const GATED = [503, { error: 503, reason: 'indexer-syncing', detail: 'indexer at height 5, target 10' }];
const INVALID = [400, { error: 400, reason: 'invalid-address', detail: 'bad checksum' }];
const FAILED = [500, { error: 500, reason: 'internal', detail: 'read failed' }];

function serve(entries) {
  routes = new Map(entries);
  location.hash = '';
}

test('authoritative refusals keep their own messages; other failures stay unavailable', async () => {
  assert.equal(explorer.lookupVerdict({ status: 400, message: 'invalid-address' }), 'invalid');
  assert.equal(explorer.lookupVerdict({ status: 503, message: 'indexer-halted' }), 'gated');
  assert.equal(explorer.lookupVerdict({ status: 503, message: 'HTTP 503' }), null);
  assert.equal(explorer.lookupVerdict({ status: 500, message: 'internal' }), null);
  assert.equal(explorer.lookupVerdict({ status: 0, message: 'request failed' }), null);

  serve([['/blockchain/indexedHeight', CAUGHT_UP], [BALANCE, INVALID]]);
  await explorer.searchQuery(ADDRESS);
  assert.equal(status(), 'not a valid address for this network');
  assert.equal(location.hash, '');

  serve([['/blockchain/indexedHeight', SYNCING], [BALANCE, GATED]]);
  await explorer.searchQuery(ADDRESS);
  assert.equal(status(), 'address lookups unavailable — extra-index still syncing');

  serve([['/blockchain/indexedHeight', CAUGHT_UP], [BALANCE, FAILED]]);
  await explorer.searchQuery(ADDRESS);
  assert.equal(status(), 'Search unavailable — a node lookup failed. Try again.');
});

test('an answered id probe routes even when another probe fails', async () => {
  serve([
    ['/blockchain/indexedHeight', CAUGHT_UP],
    [`/blocks/${ID}/header`, [200, { id: ID }]],
    [`/blockchain/box/byId/${ID}`, GATED],
    [`/blockchain/token/byId/${ID}`, FAILED],
  ]);
  await explorer.searchQuery(ID);
  assert.equal(location.hash, `explorer/block/${ID}`);

  // No hit: the index flipped to syncing after the cached caught-up read.
  serve([
    ['/blockchain/indexedHeight', [CAUGHT_UP, SYNCING]],
    [`/blockchain/box/byId/${ID}`, GATED],
    [`/blockchain/token/byId/${ID}`, GATED],
  ]);
  await explorer.searchQuery(ID);
  assert.equal(status(), 'not found — searched blocks + mempool only (extra-index still syncing)');

  // No hit and an unanswered probe: absence is not established.
  serve([['/blockchain/indexedHeight', CAUGHT_UP], [`/api/v1/transactions/${ID}/detail`, FAILED]]);
  await explorer.searchQuery(ID);
  assert.equal(status(), 'Search unavailable — a node lookup failed. Try again.');
});

test('entity views keep invalid and index-gate explanations', async () => {
  for (const kind of ['box', 'token']) {
    serve([['/blockchain/indexedHeight', SYNCING], [`/blockchain/${kind}/byId/${ID}`, GATED]]);
    explorer.onRoute(`${kind}/${ID}`);
    await settle();
    assert.equal(banner(), `${kind} not found — extra-index still syncing`);
  }

  serve([['/blockchain/indexedHeight', SYNCING], [`/blockchain/transaction/byId/${ID}`, GATED]]);
  explorer.onRoute(`tx/${ID}`);
  await settle();
  assert.equal(banner(), 'transaction not found — extra-index still syncing');

  serve([['/blockchain/indexedHeight', CAUGHT_UP], [BALANCE, INVALID]]);
  explorer.onRoute(`address/${ADDRESS}`);
  await settle();
  assert.equal(banner(), 'address not found — invalid for this network');

  // A gate that cleared before the refresh did not answer this lookup.
  serve([['/blockchain/indexedHeight', CAUGHT_UP], [`/blockchain/box/byId/${ID}`, GATED]]);
  explorer.onRoute(`box/${ID}`);
  await settle();
  assert.equal(banner(), 'Lookup unavailable — the node could not answer this request. Try again.');
});
