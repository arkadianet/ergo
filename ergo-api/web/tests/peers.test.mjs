import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';

const source = (await readFile(new URL('../js/peers.js', import.meta.url), 'utf8'))
  .replace(/^import .*;\r?\n/gm, '').replace(/^export /gm, '');

function setup() {
  const context = vm.createContext({
    createChannelSub: () => ({}), num: String, bytes: String,
  });
  vm.runInContext(source, context);
  return (expression, data) => { context.input = data; return vm.runInContext(expression, context); };
}

const peer = (at, received, overrides = {}) => ({
  addr: '[2606:4700::1]:9030', bytes_in: received, bytes_out: received / 2,
  connected_seconds: at / 1000,
  details: { sampled_at_unix_ms: at, session_id: '9223372036854775807', connection_setup_ms: 120 },
  ...overrides,
});

test('rates use sample time, survive repeated snapshots, and reset on reconnection', () => {
  const run = setup();
  assert.equal(run('sampleTraffic(input)[0].rate_in', [peer(10000, 200)]), null);
  assert.equal(run('sampleTraffic(input)[0].rate_in', [peer(15000, 1200)]), 200);
  assert.equal(run('sampleTraffic(input)[0].rate_in', [peer(15000, 1200)]), 200);
  assert.equal(run('sampleTraffic(input)[0].rate_in', [peer(20000, 1700, { connected_seconds: 2 })]), null);
  assert.equal(run('sampleTraffic(input)[0].rate_in', [peer(24000, 1900, { connected_seconds: 3 })]), null, 'new connection cannot span the preceding sampling interval');
  assert.equal(run('sampleTraffic(input)[0].rate_in', [peer(25000, 20)]), null);
  assert.equal(run('sampleTraffic(input)[0].rate_in', [peer(300000, 2000)]), null);
  run('sampleTraffic([])');
  assert.equal(run('sampleTraffic(input)[0].rate_in', [peer(305000, 3000)]), null);
});

test('search includes network identity and does not invent unavailable values', () => {
  const run = setup();
  const row = { addr: '1.2.3.4:9030', version: '6.0.2', network: { country: 'Sweden', organization: 'Example Network', asn: 64500, hostname: 'node.example.test' } };
  for (const query of ['sweden', 'example network', 'as64500', 'node.example.test', '6.0.2']) {
    assert.equal(run(`peerMatches(input, ${JSON.stringify(query)})`, row), true);
  }
  assert.equal(run("peerMatches(input, 'undefined')", row), false);
  assert.equal(run('modeName(input)', null), 'Not advertised');
  assert.equal(run('retention(input)', { blocks_to_keep: -2 }), 'UTXO bootstrap');
  assert.equal(run('modeName(input)', { state_type: 9 }), 'Unknown (9)');
});

test('lookup guidance distinguishes opt-in, initial download, and failure', () => {
  const run = setup();
  assert.match(run('peerLookupNote(input)', [{ network: { geo_status: 'not_configured' } }]), /auto_download/);
  assert.match(run('peerLookupNote(input)', [{ network: { geo_status: 'downloading' } }]), /Downloading/);
  assert.match(run('peerLookupNote(input)', [{ network: { geo_status: 'downloading', asn_status: 'error' } }]), /unavailable/);
  assert.equal(run('peerLookupNote(input)', [{ network: { geo_status: 'available', asn_status: 'available' } }]), '');
  assert.equal(run('peerLookupNote(input)', [{ network: { geo_status: 'not_public', asn_status: 'not_public' } }]), '');
});
