# Wallet path and visibility reference

`WalletPaths.scala` executes the published Sigma SDK 6.0.6 under Scala 2.12.20
using public BIP32 vector 1. It captures actual `isMaster`, `isEip3`, `nextPath`,
public keys and mainnet addresses for six small tracked-key shapes.
Run: `scala-cli run WalletPaths.scala --server=false --jvm system`.
The capture is an SDK path/address oracle; it does not execute the node's
private WalletCache visibility method.

Visibility follows the complete pinned node source
[WalletCache.scala v6.0.5](https://github.com/ergoplatform/ergo/blob/5528ef569a41ebccbc8658212e6ee3c97d990b96/src/main/scala/org/ergoplatform/nodeView/wallet/WalletCache.scala):
if the ordered tracked sequence has more than one key, starts with a master,
and its second key is EIP-3, omit that master. Otherwise expose all keys.
Complete source SHA-256: `05460eccbbe5bedfa58946265971605938e7023138d9c69974d5b983e5a072cc`.
The checked local file exactly matches the pinned tag.

The ordered sequence is the one Scala rebuilds at boot and unlock:
`WalletStorage.readAllKeys` walks its LevelDB keys bytewise, and each key ends
in the public-branch `DerivationPathSerializer` bytes (`0x01`, the ZigZag-VLQ
depth, then every index including the leading `0` as 4 big-endian bytes). The
master therefore sorts first and indices compare as unsigned integers. Scala
appends keys derived within a running session and re-sorts them at the next
unlock; the node keeps the storage order throughout. The cases here are already
in that order, so the native regression cannot tell it from insertion order;
`ergo-wallet` and `ergo-node` unit tests cover out-of-order derivations.

[SDK DerivationPath.scala v6.0.6](https://github.com/ScorexFoundation/sigmastate-interpreter/blob/ab0b15ceb9d34f2ccd6e68e3e2a8aa27cd16a042/sdk/shared/src/main/scala/org/ergoplatform/sdk/wallet/secrets/DerivationPath.scala)
checks the three-component EIP-3 account prefix, without requiring a five-part
address path. Complete source SHA-256:
`4a59c84595ea9bdf51160e35db904b4ac789baf141d723e6ab6182df054428a1`.
The checked local file exactly matches the pinned primary source.

The native regression exercises real tracked/visible table writes, live
hydration and reopening against these keys/addresses and the source-defined
visibility shapes. No funded wallet or external node is involved.

WalletPaths.scala SHA-256: `4350fc8f97e22020440e547aaac83f9d72fc77a9ebc276145fa071601f7d74e1`.

scala_6_0_6.json SHA-256: `0eb536ebcf04d01585189cc804c951760cf74ed1d75e4260db88ac196161e00e`.
