# Bounded private direct swaps

The node wallet can prepare a direct zero-fee swap against the exact canonical
Spectrum N2T v1 pool contract. Its proposition hash is
`99f30ad579a2c98ad31b432676627fcd9e303d43c06e898725f6155d8ac40aa9`.
The supported [primary Pool.sc contract](https://github.com/spectrum-finance/ergo-dex/blob/master/contracts/amm/cfmm/v1/n2t/Pool.sc)
requires the recreated pool to be output zero. Quotes use the full pool ERG
value and its R4 fee numerator; its 0.01 ERG storage floor remains in the pool.
An independently captured mainnet pool and its external identity are checked by
[adapter tests](../test-vectors/spectrum-n2t/README.md).

This adapter supports ERG-to-token and token-to-ERG direct swaps. It does not
route orders through Spectrum proxy/order contracts or support arbitrary DEX
contracts. Every constructed transaction goes through normal wallet signing,
structural validation, chain-context self-verification and private candidate
validation. No consensus rule or script validation bypass is added.

The wallet Management panel provides quote preview and explicit intent approval.
The API-key-protected routes are:

* `POST /api/v1/wallet/mining-swaps/preview`: frozen quote and complete unsigned
  transaction; nothing is submitted.
* `POST /api/v1/wallet/mining-swaps`: approve one bounded durable intent.
* `GET /api/v1/wallet/mining-swaps`: owner-only intent status.
* `POST /api/v1/wallet/mining-swaps/{id}/cancel`: cancel future work and retire
  offered private templates. Already mined work returns its mined status.

The request pins a current pool box, pool NFT, exact proposition hash, 1–32
confirmed owned P2PK funding boxes and a receiving P2PK address tracked by this
wallet. It includes an exact trade input, maximum input, explicit minimum output,
owner-approved quote, maximum slippage basis points, start/deadline heights and
1–100 attempts. Amounts are decimal strings in raw token units/nanoERG.
Each refreshed quote must meet both the explicit minimum and
`floor(approvedQuoteOutput * (10000 - maxSlippageBasisPoints) / 10000)`.
The input set never expands. Each funding box is recreated separately with its
script, registers and unrelated tokens preserved. Receiver-box dust remains in
the same wallet. There is no transaction fee output or public broadcast fallback.

Automatic refresh needs the node wallet unlocked. An Android-signed imported
transaction stays fixed: changing a pool input changes the signing message and
requires another signature. This scheduler signs with the node wallet only.
A locked node wallet waits without spending its retry allowance.

The serialized wallet writer checks intents every two seconds and attempts at
most one generation/admission per applied height. It reads private metadata once
per wake with a one-second bound. Queue errors retain exact journaled signed
bytes; uncertainty never authorizes another generation. If a pool input is
spent, the previous queue entry and its offered templates are retired before
another signing attempt. Signed bytes are committed before private admission,
so restart recovery resubmits the exact prepared generation. A spent funding
input stops automatic rebuilding.

Pool following uses retained applied block sections, following only the pinned
NFT and proposition. At most 128 blocks are searched per wake. Missing retained
history, a displaced approval origin, or an unresolved reorg prevents re-signing
and is shown in the intent detail; refresh the pool preview and approve a new
intent when needed. A changed follower anchor causes the replacement approval
block to be searched as well. Deadlines are restricted to the next 7,200 heights.
The private queue enforces the last allowed containing-block height during
selection and solution dispatch, so polling delays cannot publish work after
that boundary. Retry exhaustion and cancellation retire unpublished private work.
