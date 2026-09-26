import { test } from 'node:test';
import assert from 'node:assert/strict';
import { amount, decimal, makeIntent, checkPlan, TransactionSession } from '../js/wallet-transaction.js';

const address = '9' + 'a'.repeat(50), id = 'ab'.repeat(32), txId = 'cd'.repeat(32);
const balance = { nanoErg: { available: '10000000000' }, assets: [{ tokenId: id, amount: '9007199254740993' }] };
const recipients = () => [{ address, erg: '1', tokens: [] }];
const intent = () => makeIntent(recipients(), '0.001', balance, address);
const plan = () => ({ unsignedTransaction: { type: 'bytes', bytes: 'deadbeef' }, inputsSelected: [{ boxId: '01'.repeat(32), value: '2000000000', assets: [] }], changeOutputs: [{ nanoErg: '999000000', assets: [] }], fee: '1000000', reemissionBurn: null, asOf: 100 });
const ok = data => ({ ok: true, data });
function setup(overrides = {}, active) {
  const calls = [];
  const api = Object.fromEntries(Object.entries({
    build: async () => ok(plan()), status: async () => ok({ isUnlocked: true }),
    sign: async () => ok({ signedTransaction: { type: 'bytes', bytes: 'cafe' }, txId }),
    submitSigned: async () => ok({ accepted: true, txId }), ...overrides,
  }).map(([k, fn]) => [k, async (...args) => { calls.push([k, ...structuredClone(args)]); return fn(...args); }]));
  return { session: new TransactionSession(api, active), calls };
}

test('decimal amounts round-trip exactly including u64 token holdings', () => {
  assert.equal(amount('0.000000001'), '1');
  assert.equal(amount('9007199254740993', 0), '9007199254740993');
  assert.equal(decimal('18446744073709551615', 0), '18446744073709551615');
  assert.equal(decimal('1000000000'), '1');
  assert.equal(decimal('0'), '0');
  for (const value of ['1e3', '-1', '0', 'NaN', '1.0000000001', '1,000']) assert.throws(() => amount(value));
});
test('native intent keeps large token quantities as exact decimal strings', () => {
  const r = recipients(); r[0].tokens = [{ tokenId: id, amount: '9007199254740993', decimals: 0 }];
  const built = makeIntent(r, '0.001', balance, address);
  assert.equal(built.outputs[0].assets[0].amount, '9007199254740993');
  assert.equal(built.changeAddress, address); assert.equal(built.allowReemissionSpend, false);
  assert.equal(built.allowTokenBurn, false);
});
test('amounts across recipients plus fee cannot exceed available ERG', () => {
  const r = [...recipients(), ...recipients()]; r.forEach(x => x.erg = '5');
  assert.throws(() => makeIntent(r, '0.001', balance, address), /exceed/);
});
test('tokens are summed across recipients and duplicate rows rejected', () => {
  const r = [...recipients(), ...recipients()]; r.forEach(x => x.tokens = [{ tokenId: id, amount: '5000000000000000', decimals: 0 }]);
  assert.throws(() => makeIntent(r, '0.001', balance, address), /holdings/);
  r[0].tokens = [{ tokenId: id, amount: '1', decimals: 0 }, { tokenId: id, amount: '1', decimals: 0 }];
  assert.throws(() => makeIntent([r[0]], '0.001', balance, address), /only once/);
});
test('reject unavailable balance and malformed recipient', () => {
  assert.throws(() => makeIntent(recipients(), '0.001', null, address), /balance/);
  const r = recipients(); r[0].address = 'bad';
  assert.throws(() => makeIntent(r, '0.001', balance, address), /address/);
});
test('plan must balance ERG and preserve all token units', () => {
  assert.equal(checkPlan(intent(), plan()).fee, '1000000');
  const badErg = plan(); badErg.changeOutputs[0].nanoErg = '0';
  assert.throws(() => checkPlan(intent(), badErg), /balance/);
  const badToken = plan(); badToken.inputsSelected[0].assets = [{ tokenId: id, amount: '1' }];
  assert.throws(() => checkPlan(intent(), badToken), /balance/);
});
test('dust fee increase is allowed only when accounted for in change', () => {
  const p = plan(); p.fee = '1100000'; p.changeOutputs[0].nanoErg = '998900000';
  assert.equal(checkPlan(intent(), p).fee, '1100000');
});
test('re-emission requires explicit consent and exact accounting', () => {
  const p = plan(); p.reemissionBurn = { tokenId: id, tokensBurned: '100', nanoErgRouted: '100' };
  p.inputsSelected[0].assets = [{ tokenId: id, amount: '100' }]; p.changeOutputs[0].nanoErg = '998999900';
  assert.throws(() => checkPlan(intent(), p), /unexpectedly/);
  assert.ok(checkPlan({ ...intent(), allowReemissionSpend: true }, p));
});
test('build never signs or broadcasts', async () => {
  const { session, calls } = setup(); await session.build(intent());
  assert.deepEqual(calls.map(c => c[0]), ['build']);
});
test('confirmation signs exact reviewed bytes and submits only returned signed bytes', async () => {
  const { session, calls } = setup(); const draft = intent(); await session.build(draft);
  draft.outputs[0].value = '999'; // caller mutation cannot change the captured review
  assert.equal(session.intent.outputs[0].value, '1000000000');
  await session.confirm();
  assert.deepEqual(calls.map(c => c[0]), ['build', 'status', 'sign', 'submitSigned']);
  assert.deepEqual(calls[2][1], plan().unsignedTransaction);
  assert.deepEqual(calls[3][1], { type: 'bytes', bytes: 'cafe' });
});
test('draft edits invalidate review; signing requires a fresh build', async () => {
  const { session, calls } = setup(); await session.build(intent()); session.invalidate();
  await assert.rejects(() => session.confirm(), /review/);
  assert.equal(calls.length, 1);
});
test('late build result cannot resurrect a discarded draft', async () => {
  let resolve; const { session } = setup({ build: () => new Promise(r => resolve = r) });
  const pending = session.build(intent()); session.invalidate(); resolve(ok(plan()));
  await assert.rejects(pending, /changed/); assert.equal(session.plan, null);
});
test('locking the wallet before confirmation prevents signing', async () => {
  const { session, calls } = setup({ status: async () => ok({ isUnlocked: false }) });
  await session.build(intent()); await assert.rejects(() => session.confirm(), /access/);
  assert.deepEqual(calls.map(c => c[0]), ['build', 'status']);
});
test('authorization loss during signing prevents broadcast', async () => {
  let active = true;
  const { session, calls } = setup({ sign: async () => { active = false; return ok({ signedTransaction: { type: 'bytes', bytes: 'cafe' }, txId }); } }, () => active);
  await session.build(intent()); await assert.rejects(() => session.confirm(), /Nothing was broadcast/);
  assert.ok(!calls.some(c => c[0] === 'submitSigned'));
});
test('unknown submission outcome retries same signed bytes without rebuilding or signing', async () => {
  let attempt = 0;
  const { session, calls } = setup({ submitSigned: async () => ++attempt === 1 ? { ok: false, status: 0, reason: 'Connection lost' } : ok({ accepted: true, txId }) });
  await session.build(intent()); await assert.rejects(() => session.confirm(), /Connection lost/);
  assert.equal(session.txId, txId); await session.confirm();
  assert.equal(calls.filter(c => c[0] === 'sign').length, 1);
  assert.deepEqual(calls.filter(c => c[0] === 'submitSigned').map(c => c[1]), [{ type: 'bytes', bytes: 'cafe' }, { type: 'bytes', bytes: 'cafe' }]);
});
test('parallel confirmations cannot send twice', async () => {
  let resolve; const { session, calls } = setup({ status: () => new Promise(r => resolve = r) });
  await session.build(intent()); const pending = session.confirm();
  await assert.rejects(() => session.confirm()); resolve(ok({ isUnlocked: true })); await pending;
  assert.equal(calls.filter(c => c[0] === 'submitSigned').length, 1);
});
