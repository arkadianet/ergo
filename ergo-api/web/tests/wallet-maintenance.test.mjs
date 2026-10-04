import { test } from 'node:test';
import assert from 'node:assert/strict';
import { canCancelMaintenance, describeMaintenanceJob, eligibleFor, makeMaintenanceRequest, pendingMaintenance, recipientLines, summarizeBoxes } from '../js/wallet-maintenance.js';
const owned = { boxId: 'aa'.repeat(32), value: '9007199254740993', assets: [{ tokenId: 'bb'.repeat(32), amount: '9007199254740993' }], status: { type: 'confirmed' }, provenance: { type: 'owned' } };
const reward = { ...owned, boxId: 'cc'.repeat(32), status: { type: 'immature', maturesAtHeight: 720 }, provenance: { type: 'minerReward' } };
test('maintenance pins the reviewed boxes and preserves amounts beyond JS safe integers', () => {
  const req = makeMaintenanceRequest('consolidate', [owned], 'tracked-address', '100', '820', '10', 'Consolidate');
  assert.deepEqual(req.task, { type: 'consolidate', boxIds: [owned.boxId], destination: 'tracked-address' });
  assert.equal(req.notBeforeHeight, 100); assert.equal(req.expiresAtHeight, 820);
  const totals = summarizeBoxes([owned, reward]);
  assert.equal(totals.nanoErg, '18014398509481986'); assert.equal(totals.tokens[0].amount, '18014398509481986');
  assert.equal(req.delivery, undefined);
});
test('reward maturity is allowed to wait while other operations require confirmed owned inputs', () => {
  assert.ok(eligibleFor('rewards', reward)); assert.ok(!eligibleFor('renew', reward));
  assert.ok(!eligibleFor('rewards', owned)); assert.ok(!eligibleFor('consolidate', { ...owned, status: { type: 'spent' } }));
  assert.throws(() => makeMaintenanceRequest('consolidate', [reward], 'address', 0, 100, 1, 'label'));
});
test('a conflicted maintenance transaction remains cancellable before a rollback can revive it', () => {
  for (const state of ['waiting', 'waitingForWallet', 'prepared', 'queued', 'inCandidate', 'conflicted']) assert.ok(canCancelMaintenance(state), state);
  for (const state of ['mined', 'cancelled', 'expired', 'failed']) assert.ok(!canCancelMaintenance(state), state);
});
test('renewal approval has no destination override and rejects unbounded or ambiguous operations', () => {
  assert.deepEqual(makeMaintenanceRequest('renew', [owned], '', 100, 101, 1, 'renew').task, { type: 'renew', boxIds: [owned.boxId] });
  for (const [start, end, attempts] of [[100,100,1], [100,200,0], [100,200,101], ['1e2',200,1], [0,4294967296,1]]) assert.throws(() => makeMaintenanceRequest('renew', [owned], '', start, end, attempts, 'renew'));
  assert.throws(() => makeMaintenanceRequest('renew', [owned, owned], '', 0, 100, 1, 'renew'));
  assert.throws(() => makeMaintenanceRequest('renew', [], '', 0, 100, 1, 'renew'));
});
test('job review shows every payment recipient, amount, token and the schedule', () => {
  const intent = { outputs: [{ type: 'payment', address: 'recipient-one', value: '1500000000', assets: [{ tokenId: 'bb'.repeat(32), amount: '7' }] }, { type: 'payment', address: 'recipient-two', value: '1000000' }], fee: '0', inputs: { type: 'boxIds', boxIds: [owned.boxId] } };
  const payment = describeMaintenanceJob({ request: { label: 'pay', task: { type: 'send', intent }, notBeforeHeight: 10, expiresAtHeight: 20, maxAttempts: 1 } });
  assert.deepEqual({ kind: payment.kind, payment: payment.payment, inputs: payment.inputs, start: payment.start, expiry: payment.expiry }, { kind: 'Fixed payment', payment: true, inputs: 1, start: 10, expiry: 20 });
  assert.deepEqual(recipientLines(payment), [`Pays 1.5 ERG and 7 units of ${'bb'.repeat(32)} to recipient-one.`, 'Pays 0.001 ERG to recipient-two.']);
  const consolidation = describeMaintenanceJob({ request: { task: { type: 'consolidate', boxIds: [owned.boxId, reward.boxId], destination: 'tracked-address' }, notBeforeHeight: 1, expiresAtHeight: 2 } });
  assert.equal(consolidation.inputs, 2); assert.equal(consolidation.payment, false);
  assert.deepEqual(recipientLines(consolidation), ['All selected ERG and tokens go to tracked-address.']);
  assert.deepEqual(recipientLines(describeMaintenanceJob({ request: { task: { type: 'renew', boxIds: [owned.boxId] } } })), ['Each box returns to its current wallet recipient.']);
});
test('pending review counts jobs that can still sign and singles out payments', () => {
  const job = (state, type) => ({ state, request: { task: type === 'send' ? { type, intent: { outputs: [] } } : { type, boxIds: [] } } });
  const { pending, payments } = pendingMaintenance([job('waiting', 'send'), job('waitingForWallet', 'renew'), job('queued', 'send'), job('conflicted', 'send'), job('mined', 'send'), job('cancelled', 'send')]);
  assert.deepEqual(pending.map(item => item.state), ['waiting', 'waitingForWallet', 'queued']);
  assert.deepEqual(payments.map(item => item.state), ['waiting', 'queued']);
  assert.deepEqual(pendingMaintenance(undefined), { pending: [], payments: [] });
});
