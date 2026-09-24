import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const source = await readFile(new URL('../js/auth.js', import.meta.url), 'utf8');
let instance = 0;

async function setup(reason) {
  const storage = new Map();
  globalThis.sessionStorage = {
    getItem: (key) => storage.get(key),
    setItem: (key, value) => storage.set(key, value),
    removeItem: (key) => storage.delete(key),
  };
  const element = () => ({
    style: {}, hidden: false,
    setAttribute() {}, addEventListener() {},
    replaceChildren(...children) { this.children = children; },
  });
  globalThis.document = { createElement: element };
  const chip = element();
  const guidance = element();
  const input = element();
  const dialog = {
    ...element(),
    querySelector: (selector) => selector === '#auth-key' ? input : guidance,
  };
  const requests = [];
  globalThis.fetch = async (_url, options) => {
    requests.push(options);
    return { status: 403, json: async () => ({ reason }) };
  };
  const auth = await import('data:text/javascript;base64,' +
    Buffer.from(source + '\n// instance ' + instance++).toString('base64'));
  auth.initAuth(chip, dialog);
  await new Promise(setImmediate);
  return { auth, chip, guidance, requests };
}

// ----- happy path -----

test('auth_no_server_hash_shows_guidance_before_key_entry', async () => {
  const { auth, chip, guidance, requests } = await setup('api-key-not-configured');
  assert.equal(auth.getApiKey(), '');
  assert.equal(auth.authState(), 'unconfigured');
  assert.equal(requests.length, 1);
  assert.deepEqual(requests[0].headers, {});
  assert.equal(chip.children[1].textContent, 'API key not configured');
  assert.equal(guidance.hidden, false);
  assert.equal(guidance.textContent, 'Configure [api.security] api_key_hash, then restart');
  await auth.setApiKey('hello');
  assert.equal(auth.authState(), 'unconfigured');
  await auth.setApiKey('');
  assert.equal(auth.authState(), 'unconfigured');
});

test('auth_configured_valid_key_authorizes_and_clear_revokes', async () => {
  const { auth, guidance } = await setup('invalid.api-key');
  assert.equal(auth.authState(), 'none');
  globalThis.fetch = async () => ({ status: 200 });
  await auth.setApiKey('secret');
  assert.equal(auth.authState(), 'authorized');
  assert.equal(guidance.hidden, true);
  globalThis.fetch = async () => ({ status: 403, json: async () => ({ reason: 'invalid.api-key' }) });
  await auth.setApiKey('');
  assert.equal(auth.authState(), 'none');
});

// ----- error paths -----

test('auth_configured_wrong_key_retains_invalid_label', async () => {
  const { auth, chip } = await setup('invalid.api-key');
  await auth.setApiKey('wrong');
  assert.equal(auth.authState(), 'invalid');
  assert.equal(chip.children[1].textContent, 'Invalid key');
});

test('auth_stale_or_unrelated_errors_do_not_relabel_key', async () => {
  const { auth } = await setup('invalid.api-key');
  globalThis.fetch = async () => ({ status: 200 });
  await auth.setApiKey('current');
  auth.report(403, true, 'old', 'api-key-not-configured');
  assert.equal(auth.authState(), 'authorized');
  auth.report(403, true, 'current', 'private_key_export_disabled');
  assert.equal(auth.authState(), 'authorized');
  auth.report(403, true, 'current', 'api-key-not-configured');
  assert.equal(auth.authState(), 'unconfigured');
});

test('auth_key_change_during_probe_ignores_stale_configuration_response', async () => {
  const { auth } = await setup('invalid.api-key');
  let resolveBody;
  globalThis.fetch = async () => ({
    status: 403,
    json: () => new Promise(resolve => { resolveBody = resolve; }),
  });
  const pending = auth.setApiKey('old');
  await new Promise(setImmediate);
  globalThis.fetch = async () => ({ status: 200 });
  await auth.setApiKey('new');
  resolveBody({ reason: 'api-key-not-configured' });
  await pending;
  assert.equal(auth.authState(), 'authorized');
});
