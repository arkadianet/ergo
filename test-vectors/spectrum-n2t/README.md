# Spectrum N2T v1 direct swap oracle

`mainnet-pool.json` is the unmodified box identity, script, asset and register
fields captured on 2026-10-04 from the Ergo explorer API:
https://api.ergoplatform.com/api/v1/boxes/9189a7ebc4ca2ba5daf80a63e431fb30cd55d563e878d9085e0fcf645a8114b2

The external box ID and canonical proposition hash are asserted by the wallet
adapter tests. The independently published primary contract is:
https://github.com/spectrum-finance/ergo-dex/blob/master/contracts/amm/cfmm/v1/n2t/Pool.sc

Its swap inequality uses SELF.value (1,010,000,000 nanoERG), token reserve
1,000,000 and fee numerator 997. Independent integer arithmetic gives:

* 100,000,000 nanoERG input => floor(1,000,000 * 100,000,000 * 997 /
  (1,010,000,000 * 1000 + 100,000,000 * 997)) = 89,844 tokens.
* 100,000 tokens input => floor(1,010,000,000 * 100,000 * 997 /
  (1,000,000 * 1000 + 100,000 * 997)) = 91,567,700 nanoERG.

The tests reduce the actual captured contract against both constructed swaps,
reject one token above its inequality, and sign the pool input with an empty
proof plus a real P2PK funding proof. These are adapter tests; consensus
validation/interpreter rules remain unchanged.
