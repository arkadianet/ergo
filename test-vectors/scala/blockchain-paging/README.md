# Global range paging reference

`windows.json` is the output of `PagingProbe.scala` under Scala 2.12.20.
The probe evaluates the numeric-index selection expression from Ergo v6.0.5
`BlockchainApiRoute.getTxRange` (lines 187–194) and `getBoxRange` (340–347):
`base = globalCounter - offset`, select `base - limit + i`, then reverse.
The reference uses signed `Int` for offset and limit (line 41).

Primary source: [src/main/scala/org/ergoplatform/http/api/BlockchainApiRoute.scala](https://github.com/ergoplatform/ergo/blob/5528ef569a41ebccbc8658212e6ee3c97d990b96/src/main/scala/org/ergoplatform/http/api/BlockchainApiRoute.scala)
Revision: `5528ef569a41ebccbc8658212e6ee3c97d990b96`. Complete source blob SHA-256: `3740466836118de3db14b907606dc4af4fedaf6a9cf4e3c1b2e8808a680c633d`.
Probe SHA-256: `dd31b501baac5c142e8025bc116d4750f6eb3e906ce9c07b34c4252d4e28d5c0`.
Output SHA-256: `2ac0e600c4d09e3b8dadc819833bebc5bce9c9fb9bf57b59cbd3596002791783`.

Regenerate with `scala-cli run PagingProbe.scala --server=false`.
The probe is a finite source-expression check; it does not run a node,
query a chain, or establish consensus behavior. All reference windows are
inside the indexed domain. Native truncation of partial pages and empty
out-of-range pages are deliberate bounded API behavior tested separately;
the pinned Scala route dereferences missing indices instead.
