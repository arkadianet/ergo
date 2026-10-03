import test from 'node:test';
import assert from 'node:assert/strict';
import { swapDraft, effectiveSwapMinimum, SPECTRUM_N2T_TREE_HASH, canCancelSwap } from '../js/wallet-swaps.js';

const values = () => ({ label: 'bounded', pool: '11'.repeat(32), nft: '22'.repeat(32), funding: '33'.repeat(32), receiver: 'tracked', direction: 'ergToToken', input: '100000000', maximum: '100000000', minimum: '100', quote: '1000', slippage: '100', start: '10', expiry: '100', attempts: '3' });

test('swap approval pins exact funding, canonical contract and decimal price bounds', () => {
  const draft = swapDraft(values());
  assert.equal(draft.poolTreeHash, SPECTRUM_N2T_TREE_HASH);
  assert.deepEqual(draft.fundingBoxIds, ['33'.repeat(32)]);
  assert.equal(draft.inputAmount, '100000000');
  assert.equal(effectiveSwapMinimum(draft), '990');
  assert.equal(effectiveSwapMinimum({ ...draft, minOutputAmount: '995' }), '995');
});
test('swap approval preserves Long precision and rejects overspending', () => {
  const input = '9223372036854775807';
  assert.equal(swapDraft({ ...values(), input, maximum: input }).inputAmount, input);
  assert.throws(() => swapDraft({ ...values(), input: '100000001' }), /maximum input/);
  assert.throws(() => swapDraft({ ...values(), input: '9223372036854775808', maximum: '9223372036854775808' }), /Long/);
});
test('swap approval rejects duplicate implicit funding and unbounded retries or slippage', () => {
  assert.throws(() => swapDraft({ ...values(), funding: '' }), /funding/);
  assert.throws(() => swapDraft({ ...values(), funding: '33'.repeat(32) + ' ' + '33'.repeat(32) }), /distinct/);
  assert.throws(() => swapDraft({ ...values(), slippage: '10001' }), /slippage/);
  assert.throws(() => swapDraft({ ...values(), expiry: '10' }), /deadline/);
  assert.throws(() => swapDraft({ ...values(), attempts: '101' }), /attempts/);
});

test('swap cancellation remains available for mined and signed recoverable conflict states', () => {
  assert.equal(canCancelSwap({state:'mined',txId:'44'.repeat(32)}),true);
  assert.equal(canCancelSwap({state:'conflicted',txId:'44'.repeat(32)}),true);
  assert.equal(canCancelSwap({state:'conflicted',txId:null}),false);
  assert.equal(canCancelSwap({state:'cancelled',txId:'44'.repeat(32)}),false);
});
