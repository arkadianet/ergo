# Wallet interoperability fixtures

`scala_6_0_6.json` was generated on 2026-10-03 by the real Scala wallet and
sigma-state 6.0.6 implementations. The reference node tag `v6.0.6` resolves
to `23aabead88774d27f2c9190ace3c9abbc8f1d5cb`. The generator uses fixed salts,
IVs and public test phrases so the fixture is reproducible. These are test
wallets; never send funds to their addresses.

The script exercises `AES.encrypt`, `EncryptedSecret`'s Circe codec,
`Mnemonic.toSeed`, SDK master/child derivation and `ErgoAddressEncoder`.
It pins the historical encrypted-stream field split, absent cipher
algorithm/mode fields, a null legacy flag, the modern EIP-3 address and the
pre-1627 leading-zero derivation branch. Rust tests additionally remove the
legacy flag to cover old imports. They do not derive expected bytes using
the Rust implementation.

Install Java 17, sbt and scala-cli. Publish the reference wallet first because
`ergo-wallet` 6.0.6 is not on Maven Central:

```sh
git clone --depth 1 --branch v6.0.6 https://github.com/ergoplatform/ergo.git /tmp/ergo-wallet-reference
git -C /tmp/ergo-wallet-reference rev-parse HEAD
cd /tmp/ergo-wallet-reference
sbt "ergoWallet/publishLocal"
```

From this repository, regenerate and compare:

```sh
scala-cli run scripts/jvm_wallet_oracle/WalletOracle.scala --server=false --jvm 17 > /tmp/scala-wallet.json
diff -u test-vectors/wallet/scala_6_0_6.json /tmp/scala-wallet.json
```

The reverse check unlocks a freshly written Rust secret file and compares
the Scala-derived master key, rather than just comparing JSON:

```sh
export ERGO_WALLET_INTEROP_FILE=/tmp/rust-wallet.json
cargo test -p ergo-wallet --test it rust_generated_file_exports_for_scala_verification
scala-cli run scripts/jvm_wallet_oracle/WalletOracle.scala --server=false --jvm 17 -- verify "$ERGO_WALLET_INTEROP_FILE" test-rust-to-scala-pw
```

Both checks run in the `Scala wallet interoperability` PR job. Feature-gated
multi-signature and proving consistency targets also run explicitly in CI.
