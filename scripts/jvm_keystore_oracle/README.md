# Scala/Appkit keystore oracle

`KeystoreOracle.scala` uses the published **Appkit 6.0.1**, matching Lithos
Client, and its `ergo-wallet` 6.0.0 dependency. It calls reference `AES.encrypt`
and `JsonSecretStorage.unlock` for both HMAC-SHA256 and HMAC-SHA512, independently
derives the 256-bit key with JVM `SecretKeyFactory`, and unlocks the SHA256 file
with Appkit's unmodified `SecretStorage.loadFrom` defaults. The Unicode password
checks Java/Rust password encoding as well as encryption.

Existing Rust HMAC-SHA512 wallets can be exported for Lithos without recovering
their mnemonic or changing the original wallet:

```bash
ergo-wallet export-keystore --keystore /path/to/existing-wallet.json \
  --output-dir /path/to/new-lithos-keystore
```

Enter the existing wallet password at the hidden prompt. The command prints the
new keystore path; use it as Lithos `node.storagePath` with the same `node.pass`.
The output directory must be empty or absent. The seed, all derived keys, and
the pre-1627 derivation flag are preserved. For scripts, `--password-file <path>`
or `--password-file -` reads a password without putting it in process arguments.

Regenerate the deterministic fixture from the repository root:

```bash
scala-cli run scripts/jvm_keystore_oracle/KeystoreOracle.scala --server=false \
  > test-vectors/scala/wallet/keystore_appkit_6_0_1.json
```

Validate the opposite direction with a newly generated Rust wallet:

```bash
wallet_oracle_dir=$(mktemp -d)
cargo run -p ergo-wallet --features keystore --example export_keystore_oracle -- "$wallet_oracle_dir"
scala-cli run scripts/jvm_keystore_oracle/KeystoreOracle.scala --server=false -- \
  verify "$wallet_oracle_dir/$(ls "$wallet_oracle_dir")"
```

The output must report that Appkit unlocked the Rust wallet and recovered master
public key `03d902f35f560e0470c63313c7369168d9d7df2d49bf295fd9fb7cb109ccee0494`.
These credentials and the mnemonic are public test data; never fund this wallet.

Reference behavior:

- `SecretStorage.DEFAULT_SETTINGS` is `HmacSHA256`, 128000 iterations, 256 **bits**.
- Reference `EncryptionSettings` JSON has `prf`, `c`, and `dkLen`; it omits the
  older `encryptionAlgorithm` and `encryptionMode` fields.
- `AES.encrypt` splits JVM GCM output at its **first** 16 bytes, stores that prefix
  as `authTag`, and stores the remainder as `cipherText`. Decryption concatenates
  `authTag ++ cipherText`. This field partition differs from a conventional
  trailing GCM tag, although the authenticated combined bytes are identical.
- Appkit `loadFrom` supplies its default PRF rather than reading the file's PRF.
  SHA512 reference fixtures therefore use `JsonSecretStorage` with explicit
  settings. Rust accepts both PRFs and both historical field partitions without
  rewriting imported wallets.

Published source artifact:
<https://repo.maven.apache.org/maven2/org/ergoplatform/ergo-appkit_2.12/6.0.1/ergo-appkit_2.12-6.0.1-sources.jar>
(SHA256 `0ed57500afeee8ca4dfe13c6068d9db8cdc42be4ddc28ce83a16d18f73968c73`).
