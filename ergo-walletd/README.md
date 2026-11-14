# ergo-walletd

The standalone Ergo wallet daemon: it holds the wallet's keys, syncs from an
`ergo-node` over its authenticated API, and serves the wallet API on a local
Unix socket or loopback address. See [wallet setup](../docs/wallet-setup.md)
and the `ergo-walletd.toml` keys in
[configuration](../docs/configuration.md#ergo-walletdtoml-security).

## Message signing

`POST /api/v1/wallet/messages/sign` signs an off-chain quote with a key the
wallet tracks, so a quote key never has to sit in a file. It supports two
named schemes and nothing else:

- `kadia-maker-quote-v1`: a Kadia DEX maker-vault quote, given as its fields.
- `rosen-intents-quote-v1`: a Rosen Intents quote, given as its full
  encoding. The wallet checks the encoding and hashes it itself; it never
  signs a bare hash.

The route is off unless `[security] message_signing = true`. It needs the
wallet unlocked. The wallet's first and change keys sign only with
`"allowSpendKey": true`, so derive a separate key (`POST /wallet/deriveKey`)
for quotes.

```sh
curl --unix-socket "$SOCK" -H "api_key: $KEY" -H 'Content-Type: application/json' \
  http://localhost/api/v1/wallet/messages/sign -d '{
    "scheme": "kadia-maker-quote-v1",
    "key": {"path": "m/44'"'"'/429'"'"'/0'"'"'/0/1"},
    "message": {"vaultBoxId": "…", "side": 0, "priceNum": 1005, "priceDen": 2000,
                "minIn": 1000, "maxIn": 1000000000, "expiryHeight": 1200010,
                "execFee": 1000000}
  }'
```

[Wallet message signing](../docs/wallet-message-signing.md) gives the message
layouts, the response, and why a signature from one scheme can't be used as a
transaction proof or as the other scheme's signature.
