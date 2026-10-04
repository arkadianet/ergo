# Leading-zero master reference

Generated with `scala-cli run LeadingZeroMaster.scala --server=false` under
Scala 2.12.20 and the published `org.scorexfoundation::sigma-state:6.0.6` SDK.
Uses the public BIP32 vector 3 seed. Modern and legacy master derivation keeps
32 bytes. Legacy child derivation still strips leading zeros.
The fixture covers root, first hardened child, pre-EIP-3 and EIP-3 paths,
including private scalar, chain code, public key and mainnet P2PK address.

Primary source: [ExtendedSecretKey.scala](https://github.com/ScorexFoundation/sigmastate-interpreter/blob/ab0b15ceb9d34f2ccd6e68e3e2a8aa27cd16a042/sdk/shared/src/main/scala/org/ergoplatform/sdk/wallet/secrets/ExtendedSecretKey.scala).
Tag v6.0.6 revision `ab0b15ceb9d34f2ccd6e68e3e2a8aa27cd16a042`; complete source SHA-256 `7f2d0c5cd6fd28cf5a81b1f770ea317be989c092bb8b0e7fb9ca30abb1f1ccd6`.
Generator SHA-256 `c4cccfa2fd11f68403961822a3566614d7edf2d0d1f968ca132eb468e41a3f0e`.
Output SHA-256 `0041849b0beffcef5c6f7cb68a3b933b27920c81b52eae658dc241d123aedc4d`.

`legacy-rust-trimmed-master` is an explicitly seeded compatibility case:
the probe trims the SDK master before applying SDK legacy child derivation.
It reproduces the old Rust-specific behavior; it is not Scala's legacy master
constructor. All values are public test vectors, without funded wallet state.

## API and recovery migration

Modern callers now use `ExtendedSecretKey::derive_master_key(seed)`;
legacy callers use `ExtendedSecretKeyLegacy::derive_master_key(seed)`.
The former boolean was ignored and has been removed. Keeping the mode in
the key type preserves it throughout descendant derivation.

A legacy wallet created by the previous Rust implementation can have
addresses based on its incorrectly trimmed master when that master begins
with zero. Encrypted seed metadata alone cannot identify its producer, so the
node decides from the wallet's persisted keys. At every unlock of an existing
wallet, `SecretStorage::bind_tracked_keys` re-derives each tracked key at its
recorded path. When the corrected master reproduces all of them, it is used.
When only `ExtendedSecretKeyLegacy::derive_master_key_legacy_rust(seed)`
reproduces all of them, the node keeps that derivation for the session and
logs a warning: signing, `/wallet/getPrivateKey` and new addresses then stay on
the tree that holds the wallet's funds. The persisted keys make the same choice
on every later unlock. Any other mismatch refuses the unlock. Separately,
signing and key export never pair a stored public key with a secret that does
not control it. Addresses are never rewritten. Normal Scala legacy imports and
new legacy restores use the corrected 32-byte master; the same secret file in a
Scala node shows the corrected addresses, not the earlier Rust ones.
