# Wallet message signing

`ergo-walletd` can sign two kinds of off-chain quote with a key it holds, so a
quote key can live in the wallet instead of in a key file. It signs only these
named schemes. It never signs caller-chosen bytes or a caller-chosen hash.

| Scheme | Signs | Verified by |
|---|---|---|
| `kadia-maker-quote-v1` | a Kadia DEX maker-vault quote | the maker-vault contract |
| `rosen-intents-quote-v1` | a Rosen Intents swap quote | the intents vault contract |

## Enabling it

The route is off by default. Turn it on in `ergo-walletd.toml`:

```toml
[security]
message_signing = true
```

Without it the route returns `403 sensitive_op_disabled`. The wallet must also be unlocked
(`409 wallet_locked` otherwise), and a sealed daemon returns
`503 wallet_sealed` as for every wallet route.

## `POST /api/v1/wallet/messages/sign`

Authenticated with the local API key, like every wallet route. The response is
`Cache-Control: no-store`.

```json
{
  "scheme": "kadia-maker-quote-v1",
  "key": { "path": "m/44'/429'/0'/0/1" },
  "message": { "...": "the scheme's fields, below" },
  "allowSpendKey": false
}
```

- `key` names exactly one of `address` (a P2PK address of this network) or
  `path` (a derivation path). Either way it must be a key the wallet already
  tracks; derive one first with `POST /wallet/deriveKey`. An untracked key is
  `404 address_not_found`.
- `allowSpendKey` (default `false`): the wallet's first key
  (`m/44'/429'/0'/0/0`, `m/1` for pre-EIP-3 wallets, or the master key) and
  its change key hold the wallet's funds, so they sign only when this is
  `true` (`403 sensitive_op_disabled` otherwise). Use a separate derived key as the quote
  key.
- An unknown `scheme`, an unknown field, or a message that is not a valid
  message of the scheme is `400 bad_request`.

The response:

```json
{
  "scheme": "kadia-maker-quote-v1",
  "address": "3W…",
  "publicKey": "02…",
  "a": "03…",
  "z": "5f…",
  "signature": "03…5f…",
  "signedMessage": "6b61…"
}
```

`publicKey` is the 33-byte compressed key `Q`, `a` the 33-byte commitment, `z`
the 32-byte response, `signature` the 65 bytes `a ‖ z`, and `signedMessage` the
bytes the challenge commits to: the 112-byte maker message, or the 32-byte
Rosen quote hash. All are hex.

### `kadia-maker-quote-v1`

```json
{
  "vaultBoxId": "<32 bytes hex>",
  "side": 0, "priceNum": 1005, "priceDen": 2000,
  "minIn": 1000, "maxIn": 1000000000,
  "expiryHeight": 1200010, "execFee": 1000000
}
```

- Message: `m = "kadia-dex/maker-quote/v1" ‖ vaultBoxId ‖ side ‖ priceNum ‖
  priceDen ‖ minIn ‖ maxIn ‖ expiryHeight ‖ execFee`, each number an 8-byte
  big-endian signed integer (112 bytes).
- Challenge: `e = blake2b256("kadia-dex/maker-quote/v1" ‖ a ‖ Q ‖ m)`, read as
  an unsigned 256-bit integer. Response: `z = k + e·x mod n`. The vault checks
  `g^z == a · Q^e`, `z < n`, and that `a` is not the identity. It reads `a`
  and `z` as separate context variables.
- The wallet refuses a quote outside the vault's own ranges: `side` 0 or 1;
  `0 < priceNum, priceDen ≤ 2^62`; `0 < minIn ≤ maxIn ≤ 2^62`;
  `expiryHeight > 0`; `execFee ≥ 0`. Price, expiry and fee *policy* (how far
  from a reference price, how long a quote lives) belongs to the caller: the
  wallet has no market data.
- The nonce is deterministic and matches the reference quote signer's, so the
  same key and quote give the same signature as that signer.

### `rosen-intents-quote-v1`

```json
{ "quote": "<the full canonical quote encoding, hex>" }
```

- The wallet checks that `quote` is one canonical version-1 quote for its own
  network:
  - it begins with `"rosen-intents/quote"`, then version `1`, then the
    network byte (`0x00` mainnet, `0x10` testnet);
  - a 224-byte head, then six non-empty length-prefixed UTF-8 strings, with
    nothing after them and 1024 bytes at most;
  - amounts are non-zero and fit a signed long;
  - the UI fee is at most 10000 bps, with an all-zero fee script hash when
    there is no fee.
- Message: `h = blake2b256(quote)`. Challenge: `e = blake2b256(a ‖ h ‖ Q)`.
  The vault checks `g^z == a · Q^e` and reads `signature` (`a ‖ z`) as one
  65-byte context variable.
- The wallet hashes the quote itself and never accepts a hash. A route that
  signed any 32-byte `h` would sign for every protocol that uses this
  signature shape.

A different quote format is a new versioned scheme, never a change to an
existing one.

## Why a signature cannot be reused elsewhere

- **Between the two schemes.** The maker challenge's preimage begins with the
  24 bytes `kadia-dex/maker-quote/v1`. The Rosen challenge's preimage begins
  with a compressed point (`0x02` or `0x03`), and its message is the hash of
  bytes that begin with `rosen-intents/quote`. The wallet builds both
  preimages from typed fields, so a caller cannot make one scheme's challenge
  equal the other's.
- **Against transaction proofs.** An Ergo spending proof is a different
  object. Its Fiat–Shamir challenge is 192 bits, computed over the serialized
  proof tree and the transaction bytes, and the proof is encoded as `e ‖ z`,
  not `a ‖ z`. Neither scheme hashes transaction bytes, so no message
  signature verifies as a spending proof. The route never signs a transaction.
- **Against other protocols.** Each verifier accepts only messages that begin
  with its own domain, or that hash such bytes. The wallet refuses to sign
  anything that does not parse as the scheme's message.
- **Nonces.** `k = blake2b512(nonceDomain ‖ x ‖ Q ‖ msg) mod n`, as BIP-340
  derives them, with one nonce domain per scheme (`kadia-dex/maker-quote-nonce/v1`;
  `ergo-walletd/rosen-intents-quote-nonce/v1`). Two different messages never
  share a nonce, and the same key never reuses a nonce across schemes.
  Signing uses no RNG.

## What it does not do

- It signs no raw bytes or hashes, and no other scheme.
- It signs only with keys the wallet already tracks; it never derives a new
  key on a signing request.
- It returns no secret material and logs nothing about the key or nonce.
