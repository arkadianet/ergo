import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { mempoolView } from '../js/capabilities.js';

// Execute the shipped module with inert elements and response adapters. These
// tests check text/visibility transitions, not browser layout or networking.
class Element {
  hidden = true;
  textContent = '';
  style = {};
  value = '';
  nodes = new Map();

  querySelector(selector) {
    if (!this.nodes.has(selector)) this.nodes.set(selector, new Element());
    return this.nodes.get(selector);
  }
  querySelectorAll() { return []; }
  addEventListener() {}
  replaceChildren() {}
  setAttribute() {}
}

function mountedView(enabled) {
  const host = new Element();
  const response = { enabled, failed: false };
  const context = vm.createContext({
    host, mempoolView, Date, setTimeout, clearTimeout,
    document: { createElement: () => new Element() },
    api: {
      identity: async () => ({ mempool_enabled: response.enabled }),
      mempoolSummary: async () => response.failed ? null : {
        size: 0, capacity_count: 100, capacity_bytes: 1000,
        total_bytes: 0, revalidation_pending: 0,
      },
      mempoolTransactions: async () => response.failed ? null : { items: [] },
    },
    makeTable: () => ({ update() {} }),
    createChannelSub: () => ({ start() {}, stop() {}, isConnected: () => false }),
    erg: String, num: String, bytes: String, ageMs: String, truncMiddle: String,
    copyBtn: () => new Element(), feeCurve: () => new Element(),
  });
  const source = readFileSync(new URL('../js/mempool.js', import.meta.url), 'utf8')
    .replace(/^import .*;\r?\n/gm, '')
    .replace(/^export /gm, '');
  vm.runInContext(source, context, { filename: 'mempool.js' });
  vm.runInContext('mount(host)', context);
  return { host, response, refresh: () => vm.runInContext('onSlow()', context) };
}

for (const initiallyEnabled of [false, true]) {
  test(`failed refresh after ${initiallyEnabled ? 'an empty' : 'a disabled'} pool hides the empty claim`, async () => {
    const view = mountedView(initiallyEnabled);
    await view.refresh();
    assert.equal(view.host.querySelector('[data-empty]').hidden, false);
    view.response.enabled = true;
    view.response.failed = true;
    await view.refresh();
    assert.equal(view.host.querySelector('[data-empty]').hidden, true);
    assert.equal(view.host.querySelector('[data-count]').textContent, 'Unavailable');
    const banner = view.host.querySelector('[data-load-status]');
    assert.equal(banner.hidden, false);
    assert.match(banner.textContent, /Could not refresh/);

    view.response.failed = false;
    await view.refresh();
    assert.equal(view.host.querySelector('[data-empty]').hidden, false);
    assert.equal(banner.hidden, true);
    assert.match(view.host.querySelector('[data-empty-copy]').textContent, /New transactions will appear/);
    assert.equal(view.host.querySelector('[data-count]').textContent, '0 unconfirmed');
  });
}
