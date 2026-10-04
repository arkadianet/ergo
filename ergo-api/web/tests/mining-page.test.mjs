import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

// Execute the shipped mining page with inert elements and stub imports. These
// tests check what the page hands its panels, not browser layout or networking.
class Element {
  hidden = true;
  textContent = '';
  className = '';
  style = {};
  children = [];
  nodes = new Map();

  set innerHTML(_) {}
  querySelector(selector) {
    if (!this.nodes.has(selector)) this.nodes.set(selector, new Element());
    return this.nodes.get(selector);
  }
  querySelectorAll() { return []; }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this.children = nodes; }
  contains() { return false; }
  setAttribute() {}
  addEventListener() {}
}

function mountedPage() {
  const node = { mining: true };
  const refreshed = [];
  const context = vm.createContext({
    Date, Promise, Number, Math, String, Array, Object, Node: Element,
    document: { createElement: () => new Element(), activeElement: null },
    subscribe() {}, CONFIGURE_API_KEY: '', ENABLE_MINING: '',
    api: {
      identity: async () => ({ mining: node.mining }),
      tip: async () => null,
      info: async () => null,
      miningCandidate: async () => ({ ok: true, data: { msg: 'aa', template_seq: 1 } }),
      miningRewardAddress: async () => null,
    },
    makeTable: () => ({ update() {} }),
    erg: String, num: String, bytes: String, dur: String, truncMiddle: String, blockTime: String,
    minerNode: () => new Element(), poolLabel: () => '', fetchOwnPk() {}, ownPkHex: () => null,
    miningWork: () => new Element(), miningReward: () => new Element(),
    createMiningInspector: () => ({ refresh: async (candidate) => { refreshed.push(candidate); } }),
    miningPolicy: () => new Element(),
  });
  const source = readFileSync(new URL('../js/mining.js', import.meta.url), 'utf8')
    .replace(/^import [\s\S]*?;\r?\n/gm, '')
    .replace(/^export /gm, '');
  vm.runInContext(source, context, { filename: 'mining.js' });
  vm.runInContext('mount(new Node())', context);
  return { node, refreshed, refresh: () => vm.runInContext('onSlow()', context) };
}

test('the inspector stops showing work once mining is disabled', async () => {
  const page = mountedPage();
  await page.refresh();
  assert.equal(page.refreshed.at(-1)?.data?.msg, 'aa');
  // The node restarted with mining disabled while the page stayed open.
  page.node.mining = false;
  await page.refresh();
  assert.equal(page.refreshed.at(-1), null, 'retired work is not presented as current');
});
