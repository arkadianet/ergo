import { test } from 'node:test';
import assert from 'node:assert/strict';

globalThis.location = { search: '' };
globalThis.sessionStorage = { getItem: () => null, removeItem() {} };
const { sealedWalletStatus } = await import('../js/wallet.js');

test('a sealed wallet daemon is shown as an initialized, locked wallet', () => {
  const sealed = sealedWalletStatus({ ok: false, status: 503, data: { reason: 'wallet_sealed', detail: 'unseal or unlock the wallet first' }, reason: 'wallet_sealed' });
  assert.equal(sealed.isInitialized, true);
  assert.equal(sealed.isUnlocked, false);
  assert.match(sealed.error, /wallet password/);
});

test('other failures stay unavailable', () => {
  for (const res of [
    { ok: false, status: 503, data: { reason: 'node_unavailable' }, reason: 'node_unavailable' },
    { ok: false, status: 503, data: null, reason: null },
    { ok: false, status: 500, data: { reason: 'wallet_sealed' }, reason: 'wallet_sealed' },
    { ok: false, status: 0, data: null, reason: 'request-failed' },
  ]) assert.equal(sealedWalletStatus(res), null);
});

const { daemonLink } = await import('../js/moved-wallet.js');

test('the node wallet page links only to an http(s) daemon address it reported', () => {
  assert.equal(daemonLink({ reason: 'wallet_moved', address: 'http://127.0.0.1:3033' }), 'http://127.0.0.1:3033/');
  assert.equal(daemonLink({ reason: 'wallet_moved', address: 'https://wallet.example:8443/' }), 'https://wallet.example:8443/');
  for (const body of [
    { reason: 'wallet_moved' },
    { reason: 'wallet_moved', address: 'javascript:alert(1)' },
    { reason: 'wallet_moved', address: 'not a url' },
    { reason: 'wallet_moved', address: 42 },
    { reason: 'not_found', address: 'http://127.0.0.1:3033' },
    null,
  ]) assert.equal(daemonLink(body), null);
});
