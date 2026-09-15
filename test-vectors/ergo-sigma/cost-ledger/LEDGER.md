# JIT-cost conformance ledger

Generated from `ledger.toml` by `scripts/cost-ledger.py render` — do not edit by hand.

Source ledger: sigmastate `v6.0.2 23dd29f612249c169d09fae9bca76d7cc02e144c`, ergo `v6.0.2 2cdbb8cf09d7ccbc060e1022e3c15bcf6a9991b1`. Oracle: ergo 6.0.5 (sigmastate 6.0.6) localhost:9053. Updated 2026-09-15.

## Coverage

| category | OPEN | CLOSED | DIVERGENT | N-A | total |
|---|---:|---:|---:|---:|---:|
| OP | 98 | 0 | 0 | 3 | 101 |
| METHOD | 62 | 0 | 0 | 0 | 62 |
| EVAL | 23 | 0 | 0 | 1 | 24 |
| INTERP | 11 | 1 | 0 | 0 | 12 |
| ROUND | 2 | 1 | 0 | 0 | 3 |
| ORDER | 8 | 0 | 0 | 0 | 8 |
| LIMIT | 3 | 0 | 0 | 0 | 3 |
| TX | 6 | 0 | 0 | 0 | 6 |
| BLOCK | 8 | 0 | 0 | 0 | 8 |
| VERSION | 9 | 0 | 0 | 1 | 10 |
| **all** | 230 | 2 | 0 | 5 | 237 |

States: OPEN = no independent-oracle evidence yet; CLOSED = named passing test with an independent oracle; DIVERGENT = confirmed mismatch, fix pending; N-A = reviewed rationale in note.

## OP

| id | state | Scala | Rust | layers | tests | note |
|---|---|---|---|---|---|---|
| `OP-0x72` | OPEN | ValUse.costKind FixedCost(5) | `ergo-sigma/src/cost_table.rs:31` | L1,L2 | — |  |
| `OP-0x73` | OPEN | ConstantPlaceholder.costKind FixedCost(1) | `ergo-sigma/src/cost_table.rs:32` | L1,L2 | — | charged before bounds check (ORDER-constplaceholder) |
| `OP-0x74` | OPEN | SubstConstants.costKind PerItemCost(100,100,1) | `ergo-sigma/src/cost_table.rs` | L1,L2 | — |  |
| `OP-0x7A` | OPEN | LongToByteArray.costKind FixedCost(17) | `ergo-sigma/src/cost_table.rs` | L1,L2 | — |  |
| `OP-0x7B` | OPEN | ByteArrayToBigInt.costKind FixedCost(30) | `ergo-sigma/src/cost_table.rs` | L1,L2 | — |  |
| `OP-0x7C` | OPEN | ByteArrayToLong.costKind FixedCost(16) | `ergo-sigma/src/cost_table.rs` | L1,L2 | — |  |
| `OP-0x7D` | OPEN | Downcast.costKind TypeBasedCost (10 / 30 BigInt-family) | `ergo-sigma/src/evaluator/opcodes/cast.rs:16` | L1,L2 | — | dynamic; table Fixed(10) is not the whole rule |
| `OP-0x7E` | OPEN | Upcast.costKind TypeBasedCost (10 / 30 BigInt-family) | `ergo-sigma/src/evaluator/opcodes/cast.rs:16` | L1,L2 | — | dynamic |
| `OP-0x7F` | OPEN | TrueLeaf.costKind FixedCost(5) | `ergo-sigma/src/cost_table.rs:34` | L1,L2 | — |  |
| `OP-0x80` | OPEN | FalseLeaf.costKind FixedCost(5) | `ergo-sigma/src/cost_table.rs:35` | L1,L2 | — |  |
| `OP-0x81` | N-A | UnitConstant — no serializer registration | `ergo-sigma/src/cost_table.rs:161` | L1 | — | unreachable from wire bytes; parser rejects bare opcode (costing.md §4) |
| `OP-0x82` | OPEN | GroupGenerator.costKind FixedCost(10) | `ergo-sigma/src/cost_table.rs` | L1,L2 | — |  |
| `OP-0x83` | OPEN | ConcreteCollection.costKind FixedCost(20) | `ergo-sigma/src/cost_table.rs:36` | L1,L2 | — | candidate: JVM-verbatim vector test-vectors/scala/bool_collection_logical_cost.json (difftest regressions) — annotate with `// ledger:` to close |
| `OP-0x85` | OPEN | ConcreteCollectionBooleanConstant shares ConcreteCollection.costKind | `ergo-sigma/src/cost_table.rs` | L1,L2 | — |  |
| `OP-0x86` | OPEN | Tuple.costKind FixedCost(15) | `ergo-sigma/src/cost_table.rs:37` | L1,L2 | — |  |
| `OP-0x87-0x8B` | N-A | Select1..Select5 — no serializer registration | `ergo-sigma/src/cost_table.rs:39` | L1 | — | only SelectField (0x8C) is registered; unreachable |
| `OP-0x8C` | OPEN | SelectField.costKind FixedCost(10) | `ergo-sigma/src/cost_table.rs:38` | L1,L2 | — |  |
| `OP-0x8F` | OPEN | LT.costKind FixedCost(20) | `ergo-sigma/src/cost_table.rs:45` | L1,L2 | — |  |
| `OP-0x90` | OPEN | LE.costKind FixedCost(20) | `ergo-sigma/src/cost_table.rs:46` | L1,L2 | — |  |
| `OP-0x91` | OPEN | GT.costKind FixedCost(20) | `ergo-sigma/src/cost_table.rs:47` | L1,L2 | — |  |
| `OP-0x92` | OPEN | GE.costKind FixedCost(20) | `ergo-sigma/src/cost_table.rs:48` | L1,L2 | — |  |
| `OP-0x93` | OPEN | EQ — DynamicCost via DataValueComparer.equalDataValues | `ergo-sigma/src/evaluator/cost.rs::eq_with_cost` | L2 | — | no static row; see EVAL-eq-* |
| `OP-0x94` | OPEN | NEQ — DynamicCost, same as EQ | `ergo-sigma/src/evaluator/cost.rs::eq_with_cost` | L2 | — |  |
| `OP-0x95` | OPEN | If.costKind FixedCost(10) | `ergo-sigma/src/cost_table.rs:61` | L1,L2 | — |  |
| `OP-0x96` | OPEN | AND.costKind PerItemCost(10,5,32) | `ergo-sigma/src/cost_table.rs:62` | L1,L2 | — | candidate: bool_collection_logical_cost.json — annotate to close |
| `OP-0x97` | OPEN | OR.costKind PerItemCost(5,5,64) | `ergo-sigma/src/cost_table.rs:63` | L1,L2 | — | candidate: bool_collection_logical_cost.json — annotate to close |
| `OP-0x98` | OPEN | AtLeast.costKind PerItemCost(20,3,5) via addSeqCost over children | `ergo-sigma/src/cost_table.rs` | L1,L2 | — |  |
| `OP-0x99` | OPEN | Minus FixedCost(15) / BigInt 20 (TypeBased) | `ergo-sigma/src/cost_table.rs:69,231` | L1,L2 | — | arith_cost dynamic |
| `OP-0x9A` | OPEN | Plus FixedCost(15) / BigInt 20 | `ergo-sigma/src/cost_table.rs:68,231` | L1,L2 | — |  |
| `OP-0x9B` | OPEN | Xor(byte arrays).costKind PerItemCost(10,2,128) | `ergo-sigma/src/cost_table.rs` | L1,L2 | — | also reached via Global.xor (106,2) |
| `OP-0x9C` | OPEN | Multiply FixedCost(15) / BigInt 25 | `ergo-sigma/src/cost_table.rs:70,233` | L1,L2 | — |  |
| `OP-0x9D` | OPEN | Division FixedCost(15) / BigInt 25 | `ergo-sigma/src/cost_table.rs:71,233` | L1,L2 | — |  |
| `OP-0x9E` | OPEN | Modulo FixedCost(15) / BigInt 25 | `ergo-sigma/src/cost_table.rs:72,233` | L1,L2 | — |  |
| `OP-0x9F` | OPEN | Exponentiate.costKind FixedCost(900) | `ergo-sigma/src/cost_table.rs` | L1,L2 | — | also GroupElement.exp method (7,6); 6.0.6 'audit Exponentiate' commit in reconciliation |
| `OP-0xA0` | OPEN | MultiplyGroup.costKind FixedCost(40) | `ergo-sigma/src/cost_table.rs` | L1,L2 | — |  |
| `OP-0xA1` | OPEN | Min FixedCost(5) / BigInt 10 | `ergo-sigma/src/cost_table.rs:73,235` | L1,L2 | — |  |
| `OP-0xA2` | OPEN | Max FixedCost(5) / BigInt 10 | `ergo-sigma/src/cost_table.rs:74,235` | L1,L2 | — |  |
| `OP-0xA3` | OPEN | Height.costKind FixedCost(26) | `ergo-sigma/src/cost_table.rs:78` | L1,L2 | — |  |
| `OP-0xA4` | OPEN | Inputs.costKind FixedCost(10) | `ergo-sigma/src/cost_table.rs:79` | L1,L2 | — |  |
| `OP-0xA5` | OPEN | Outputs.costKind FixedCost(10) | `ergo-sigma/src/cost_table.rs:80` | L1,L2 | — |  |
| `OP-0xA6` | OPEN | LastBlockUtxoRootHash.costKind FixedCost(15) | `ergo-sigma/src/cost_table.rs` | L1,L2,L4 | — | L4 context currently approximates prevStateRoot (PROVISIONING.md) |
| `OP-0xA7` | OPEN | Self.costKind FixedCost(10) | `ergo-sigma/src/cost_table.rs:81` | L1,L2 | — |  |
| `OP-0xAC` | OPEN | MinerPubkey.costKind FixedCost(20) | `ergo-sigma/src/cost_table.rs:82` | L1,L2 | — |  |
| `OP-0xAD` | OPEN | MapCollection.costKind PerItemCost(20,1,10) | `ergo-sigma/src/cost_table.rs` | L1,L2 | — | +AddToEnv per element (EVAL-addtoenv) |
| `OP-0xAE` | OPEN | Exists.costKind PerItemCost(3,1,10) | `ergo-sigma/src/cost_table.rs` | L1,L2 | — |  |
| `OP-0xAF` | OPEN | ForAll.costKind PerItemCost(3,1,10) | `ergo-sigma/src/cost_table.rs` | L1,L2 | — |  |
| `OP-0xB0` | OPEN | Fold.costKind PerItemCost(3,1,10) | `ergo-sigma/src/cost_table.rs` | L1,L2 | — |  |
| `OP-0xB1` | OPEN | SizeOf.costKind FixedCost(14) | `ergo-sigma/src/cost_table.rs` | L1,L2 | — |  |
| `OP-0xB2` | OPEN | ByIndex.costKind FixedCost(30) | `ergo-sigma/src/cost_table.rs` | L1,L2 | — |  |
| `OP-0xB3` | OPEN | Append.costKind PerItemCost(20,2,100) | `ergo-sigma/src/cost_table.rs` | L1,L2 | — |  |
| `OP-0xB4` | OPEN | Slice.costKind PerItemCost(10,2,100) | `ergo-sigma/src/cost_table.rs` | L1,L2 | — |  |
| `OP-0xB5` | OPEN | Filter.costKind PerItemCost(20,1,10) | `ergo-sigma/src/cost_table.rs` | L1,L2 | — |  |
| `OP-0xB6` | OPEN | CreateAvlTree.costKind = notSupportedError | `ergo-sigma/src/evaluator/opcodes/errors.rs:90` | L1,L2 | — | zero-cost reject; prove no charge before the error |
| `OP-0xB7` | OPEN | TreeLookup.costKind = notSupportedError | `ergo-sigma/src/evaluator/opcodes/errors.rs:90` | L1,L2 | — | zero-cost reject |
| `OP-0xC1` | OPEN | ExtractAmount.costKind FixedCost(8) | `ergo-sigma/src/cost_table.rs:87` | L1,L2 | — |  |
| `OP-0xC2` | OPEN | ExtractScriptBytes.costKind FixedCost(10) | `ergo-sigma/src/cost_table.rs:88` | L1,L2 | — |  |
| `OP-0xC3` | OPEN | ExtractBytes.costKind FixedCost(12) | `ergo-sigma/src/cost_table.rs` | L1,L2 | — |  |
| `OP-0xC4` | OPEN | ExtractBytesWithNoRef.costKind FixedCost(12) | `ergo-sigma/src/cost_table.rs` | L1,L2 | — |  |
| `OP-0xC5` | OPEN | ExtractId.costKind FixedCost(12) | `ergo-sigma/src/cost_table.rs:89` | L1,L2 | — |  |
| `OP-0xC6` | OPEN | ExtractRegisterAs.costKind FixedCost(50) | `ergo-sigma/src/cost_table.rs` | L1,L2 | — | also charged by Box.getReg methods (99,7)/(99,19) |
| `OP-0xC7` | OPEN | ExtractCreationInfo.costKind FixedCost(16) | `ergo-sigma/src/cost_table.rs` | L1,L2 | — |  |
| `OP-0xCB` | OPEN | CalcBlake2b256.costKind PerItemCost(20,7,128) | `ergo-sigma/src/cost_table.rs` | L1,L2 | — |  |
| `OP-0xCC` | OPEN | CalcSha256.costKind PerItemCost(80,8,64) | `ergo-sigma/src/cost_table.rs` | L1,L2 | — |  |
| `OP-0xCD` | OPEN | CreateProveDlog.costKind FixedCost(10) | `ergo-sigma/src/cost_table.rs` | L1,L2 | — |  |
| `OP-0xCE` | OPEN | CreateProveDHTuple.costKind FixedCost(20) | `ergo-sigma/src/cost_table.rs` | L1,L2 | — |  |
| `OP-0xCF` | OPEN | SigmaPropIsProven = notSupportedError | `ergo-sigma/src/evaluator/opcodes/errors.rs:90` | L1 | — | zero-cost reject |
| `OP-0xD0` | OPEN | SigmaPropBytes.costKind PerItemCost(35,6,1) | `ergo-sigma/src/cost_table.rs` | L1,L2 | — |  |
| `OP-0xD1` | OPEN | BoolToSigmaProp.costKind FixedCost(15) | `ergo-sigma/src/cost_table.rs` | L1,L2 | — | also the implicit v3 Bool-root coercion (VERSION-v3-bool-root) |
| `OP-0xD4` | OPEN | DeserializeContext.costKind PerItemCost(1,10,128) | `ergo-sigma/src/cost_table.rs` | L1,L2 | — | + INTERP-deser-subst init cost; + EVAL-hasdeserialize fork |
| `OP-0xD5` | OPEN | DeserializeRegister.costKind PerItemCost(1,10,128) | `ergo-sigma/src/cost_table.rs` | L1,L2 | — |  |
| `OP-0xD6` | OPEN | ValDef — AddToEnvironment FixedCost(5) per BlockValue item | `ergo-sigma/src/evaluator/opcodes/binding.rs:81` | L1,L2 | — | charged AFTER rhs eval (ORDER-blockvalue-valdef) |
| `OP-0xD7` | OPEN | FunDef standalone = notSupportedError | `ergo-sigma/src/evaluator/opcodes/errors.rs:90` | L1 | — | zero-cost reject |
| `OP-0xD8` | OPEN | BlockValue.costKind PerItemCost(1,1,10) | `ergo-sigma/src/evaluator/opcodes/binding.rs:76` | L1,L2 | — |  |
| `OP-0xD9` | OPEN | FuncValue.costKind FixedCost(5) | `ergo-sigma/src/evaluator/opcodes/binding.rs:222` | L1,L2 | — | creation only |
| `OP-0xDA` | OPEN | Apply.costKind FixedCost(30) + AddToEnvironment(5) per call | `ergo-sigma/src/evaluator/opcodes/binding.rs:265,295` | L1,L2 | — | codex enumeration: FuncApplyCode belongs to Apply |
| `OP-0xDB` | OPEN | PropertyCall.costKind FixedCost(4) | `ergo-sigma/src/evaluator/opcodes/property_call.rs:38` | L1,L2 | — |  |
| `OP-0xDC` | OPEN | MethodCall.costKind FixedCost(4) | `ergo-sigma/src/evaluator/opcodes/method_call/mod.rs` | L1,L2 | — |  |
| `OP-0xDD` | OPEN | Global.costKind FixedCost(5) | `ergo-sigma/src/cost_table.rs:84` | L1,L2 | — |  |
| `OP-0xDF` | N-A | NoneValue — no serializer registration | `ergo-sigma/src/cost_table.rs:110` | L1 | — | flows through constant encoding; bare opcode rejected by parser |
| `OP-0xE3` | OPEN | GetVar.costKind FixedCost(10) | `ergo-sigma/src/cost_table.rs` | L1,L2 | — | also Context.getVarFromInput (101,12) charges this row |
| `OP-0xE4` | OPEN | OptionGet.costKind FixedCost(15) | `ergo-sigma/src/cost_table.rs` | L1,L2 | — |  |
| `OP-0xE5` | OPEN | OptionGetOrElse.costKind FixedCost(20) | `ergo-sigma/src/cost_table.rs` | L1,L2 | — |  |
| `OP-0xE6` | OPEN | OptionIsDefined.costKind FixedCost(10) | `ergo-sigma/src/cost_table.rs` | L1,L2 | — |  |
| `OP-0xE7-0xE9` | OPEN | ModQ / PlusModQ / MinusModQ = notSupportedError | `ergo-sigma/src/evaluator/opcodes/errors.rs:90` | L1 | — | zero-cost reject |
| `OP-0xEA` | OPEN | SigmaAnd.costKind PerItemCost(10,2,1) | `ergo-sigma/src/cost_table.rs` | L1,L2 | — |  |
| `OP-0xEB` | OPEN | SigmaOr.costKind PerItemCost(10,2,1) | `ergo-sigma/src/cost_table.rs` | L1,L2 | — |  |
| `OP-0xEC` | OPEN | BinOr.costKind FixedCost(20) | `ergo-sigma/src/cost_table.rs:64` | L1,L2 | — | short-circuit: right operand uncosted when left is true |
| `OP-0xED` | OPEN | BinAnd.costKind FixedCost(20) | `ergo-sigma/src/cost_table.rs:65` | L1,L2 | — | short-circuit |
| `OP-0xEE` | OPEN | DecodePoint.costKind FixedCost(300) | `ergo-sigma/src/cost_table.rs` | L1,L2 | — |  |
| `OP-0xEF` | OPEN | LogicalNot.costKind FixedCost(15) | `ergo-sigma/src/cost_table.rs` | L1,L2,L4 | — | was Fixed(20): found by cost_parity 889k (trace_mismatch_889k.rs); fixed; needs a tracked independent vector to CLOSE |
| `OP-0xF0` | OPEN | Negation.costKind FixedCost(30) | `ergo-sigma/src/cost_table.rs:75` | L1,L2 | — |  |
| `OP-0xF1` | OPEN | BitInversion = notSupportedError | `ergo-sigma/src/evaluator/opcodes/errors.rs:90` | L1 | — | zero-cost reject |
| `OP-0xF2` | OPEN | BitOr.costKind FixedCost(1) then not-supported | `ergo-sigma/src/cost_table.rs:182` | L1,L2 | — | charge-then-reject |
| `OP-0xF3` | OPEN | BitAnd.costKind FixedCost(1) then not-supported | `ergo-sigma/src/cost_table.rs:182` | L1,L2 | — | charge-then-reject |
| `OP-0xF4` | OPEN | BinXor.costKind FixedCost(20) | `ergo-sigma/src/cost_table.rs` | L1,L2 | — |  |
| `OP-0xF5` | OPEN | BitXor.costKind FixedCost(1) then not-supported | `ergo-sigma/src/cost_table.rs:182` | L1,L2 | — |  |
| `OP-0xF6` | OPEN | BitShiftRight.costKind FixedCost(1) then not-supported | `ergo-sigma/src/cost_table.rs:182` | L1,L2 | — |  |
| `OP-0xF7` | OPEN | BitShiftLeft.costKind FixedCost(1) then not-supported | `ergo-sigma/src/cost_table.rs:182` | L1,L2 | — |  |
| `OP-0xF8` | OPEN | BitShiftRightZeroed.costKind FixedCost(1) then not-supported | `ergo-sigma/src/cost_table.rs:182` | L1,L2 | — |  |
| `OP-0xFE` | OPEN | Context.costKind FixedCost(1) | `ergo-sigma/src/cost_table.rs:83` | L1,L2 | — |  |
| `OP-0xFF` | OPEN | XorOf.costKind PerItemCost(20,5,32) | `ergo-sigma/src/cost_table.rs` | L1,L2 | — |  |

## METHOD

| id | state | Scala | Rust | layers | tests | note |
|---|---|---|---|---|---|---|
| `METHOD-context-dataInputs` | OPEN | SContextMethods.dataInputs 15 | `ergo-sigma/src/evaluator/opcodes/property_call.rs` | L1,L2 | — |  |
| `METHOD-context-headers` | OPEN | SContextMethods.headers 15 | `property_call.rs` | L1,L2 | — | window-size divergence family #238 resolved separately |
| `METHOD-context-preHeader` | OPEN | SContextMethods.preHeader 15 | `property_call.rs` | L1,L2 | — |  |
| `METHOD-context-selfBoxIndex` | OPEN | SContextMethods.selfBoxIndex 20 (pre-JIT returns -1, sigmastate#603) | `property_call.rs` | L1,L2 | — | VERSION-selfboxindex-bug |
| `METHOD-context-lastBlockUtxoRootHash` | OPEN | SContextMethods.LastBlockUtxoRootHash 15 | `property_call.rs` | L1,L2 | — |  |
| `METHOD-context-minerPubKey` | OPEN | SContextMethods.minerPubKey 20 | `property_call.rs` | L1,L2 | — |  |
| `METHOD-context-getVarFromInput` | OPEN | SContextMethods.getVarFromInput (v6) — charges GetVar cost | `method_call/misc.rs:904` | L1,L2 | — |  |
| `METHOD-header-props` | OPEN | SHeaderMethods 1..15 property accessors 10 each | `property_call.rs` | L1,L2 | — |  |
| `METHOD-header-checkPow` | OPEN | SHeaderMethods.checkPow (v6) FixedCost(700) | `method_call/misc.rs:183` | L1,L2 | — |  |
| `METHOD-preheader-props` | OPEN | SPreHeaderMethods 1..7 accessors 10 each | `property_call.rs` | L1,L2 | — |  |
| `METHOD-global-groupGenerator` | OPEN | SGlobalMethods.groupGenerator 10 | `property_call.rs` | L1,L2 | — |  |
| `METHOD-global-xor` | OPEN | SGlobalMethods.xor → Xor PerItemCost(10,2,128) | `method_call/global.rs:312` | L1,L2 | — |  |
| `METHOD-global-serialize` | OPEN | SGlobalMethods.serialize (v6): StartWriterCost 10 + SigmaByteWriter per-put model | `method_call/global.rs:333-660` | L1,L2 | — | per-put model is the largest hand-ported formula; needs many vectors |
| `METHOD-global-deserializeTo` | OPEN | SGlobalMethods.deserializeTo (v6) PerItemCost(100,32,32) | `method_call/global.rs:186` | L1,L2 | — |  |
| `METHOD-global-fromBigEndianBytes` | OPEN | SGlobalMethods.fromBigEndianBytes (v6) 10 | `method_call/global.rs:253` | L1,L2 | — |  |
| `METHOD-global-encodeNbits` | OPEN | SGlobalMethods.encodeNbits (v6) 25 | `method_call/global.rs:35` | L1,L2 | — |  |
| `METHOD-global-decodeNbits` | OPEN | SGlobalMethods.decodeNbits (v6) 50 | `method_call/global.rs:55` | L1,L2 | — |  |
| `METHOD-global-powHit` | OPEN | SGlobalMethods.powHit (v6) — formula | `method_call/global.rs:90-153` | L1,L2 | — | dynamic pow_cost; formula must be pinned |
| `METHOD-global-some` | OPEN | SGlobalMethods.some (v6) 5 | `method_call/global.rs:72` | L1,L2 | — |  |
| `METHOD-global-none` | OPEN | SGlobalMethods.none (v6) 5 | `property_call.rs` | L1,L2 | — |  |
| `METHOD-box-tokens` | OPEN | SBoxMethods.tokens 15 | `property_call.rs` | L1,L2 | — |  |
| `METHOD-box-getReg` | OPEN | SBoxMethods.getReg (v5 (99,7) and v6 typed (99,19)) — ExtractRegisterAs cost 50 | `method_call/misc.rs:779,837` | L1,L2 | — |  |
| `METHOD-avl-props` | OPEN | SAvlTreeMethods digest/enabledOperations/keyLength/valueLengthOpt/isInsertAllowed/isUpdateAllowed/isRemoveAllowed 15 each | `property_call.rs` | L1,L2 | — |  |
| `METHOD-avl-updateOperations` | OPEN | SAvlTreeMethods.updateOperations FixedCost(45) | `method_call/avl.rs:550` | L1,L2 | — |  |
| `METHOD-avl-updateDigest` | OPEN | SAvlTreeMethods.updateDigest FixedCost(40) | `method_call/avl.rs:511` | L1,L2 | — |  |
| `METHOD-avl-contains` | OPEN | contains: CreateAvlVerifier PerItemCost(110,20,64) over proof len + LookupAvlTree PerItemCost(40,10,1) over height | `method_call/avl.rs:62-70` | L2 | — | avl_scala_oracle_parity.rs has JVM vectors; name the closing tests |
| `METHOD-avl-get` | OPEN | get: same as contains | `method_call/avl.rs:129-137` | L2 | — |  |
| `METHOD-avl-getMany` | OPEN | getMany: CreateAvlVerifier + LookupAvlTree per key | `method_call/avl.rs:222-230` | L2 | — |  |
| `METHOD-avl-insert` | OPEN | insert: isInsertAllowed 15; CreateAvlVerifier; InsertIntoAvlTree PerItemCost(40,10,1) over max(height,1) per entry; updateDigest_Info 40 on success | `method_call/avl.rs:662-700` | L2 | — |  |
| `METHOD-avl-update` | OPEN | update: isUpdateAllowed 15; CreateAvlVerifier; UpdateAvlTree PerItemCost(120,20,1); updateDigest_Info 40 | `method_call/avl.rs:668-700` | L2 | — |  |
| `METHOD-avl-insertOrUpdate` | OPEN | insertOrUpdate (v6): isUpdateAllowed 15 + isInsertAllowed 15; CreateAvlVerifier; (120,20,1); updateDigest_Info 40 | `method_call/avl.rs:674-700` | L2 | — |  |
| `METHOD-avl-remove` | OPEN | remove: isRemoveAllowed 15; CreateAvlVerifier; RemoveAvlTree PerItemCost(100,15,1) per key (cfor); digest_Info 15 unconditional; updateDigest_Info 40 on success | `method_call/avl.rs:435-467` | L2 | — |  |
| `METHOD-coll-indices` | OPEN | SCollectionMethods.IndicesMethod_CostKind PerItemCost(20,2,16) | `property_call.rs:342` | L1,L2 | — |  |
| `METHOD-coll-reverse` | OPEN | SCollectionMethods.reverse (v6) PerItemCost(20,2,100) | `property_call.rs` | L1,L2 | — |  |
| `METHOD-coll-indexOf` | OPEN | indexOf: equalDataValues per iteration + PerItemCost(20,10,2) over iterations | `method_call/coll.rs:28-70` | L2 | — | finding #15 fixed here |
| `METHOD-coll-zip` | OPEN | zip PerItemCost(10,1,10) over xs.length | `method_call/coll.rs:89` | L1,L2 | — |  |
| `METHOD-coll-startsEndsWith` | OPEN | methods.scala:1143-1158 startsWith/endsWith (v6) Zip_CostKind PerItemCost(10,1,10) over xs.length (RECEIVER length) | `method_call/coll.rs:134` | L1,L2 | — | verify Rust uses the receiver length, not the argument length |
| `METHOD-coll-get` | OPEN | get (v6) FixedCost(30) | `method_call/coll.rs:174` | L1,L2 | — |  |
| `METHOD-coll-flatMap` | OPEN | FlatMapMethod_CostKind PerItemCost(60,10,8) over OUTPUT length | `method_call/coll.rs:460` | L1,L2 | — |  |
| `METHOD-coll-patch` | OPEN | PatchMethod PerItemCost(30,2,10) over xs.length + patch.length | `method_call/coll.rs:552` | L1,L2 | — |  |
| `METHOD-coll-updated` | OPEN | UpdatedMethod PerItemCost(20,1,10) over length | `method_call/coll.rs:652` | L1,L2 | — |  |
| `METHOD-coll-updateMany` | OPEN | UpdateManyMethod PerItemCost(20,2,10) over receiver length, before op | `method_call/coll.rs:888` | L1,L2 | — |  |
| `METHOD-option-map` | OPEN | SOptionMethods.map 20 (+AddToEnv 5 when Some) | `method_call/option.rs:25,39` | L1,L2 | — |  |
| `METHOD-option-filter` | OPEN | SOptionMethods.filter 20 | `method_call/option.rs:83` | L1,L2 | — |  |
| `METHOD-groupelement-getEncoded` | OPEN | SGroupElementMethods.getEncoded FixedCost(250) | `property_call.rs` | L1,L2 | — |  |
| `METHOD-groupelement-negate` | OPEN | SGroupElementMethods.negate FixedCost(45) | `property_call.rs` | L1,L2 | — |  |
| `METHOD-groupelement-exp` | OPEN | SGroupElementMethods.exp → Exponentiate 900 | `method_call/misc.rs:237` | L1,L2 | — |  |
| `METHOD-numeric-toBytes-toBits` | OPEN | SNumericTypeMethods toBytes/toBits (v6) 5 | `property_call.rs` | L1,L2 | — |  |
| `METHOD-numeric-bitwise` | OPEN | SNumericTypeMethods bitwiseInverse/Or/And/Xor (v6) 5 | `method_call/numeric.rs:43` | L1,L2 | — |  |
| `METHOD-numeric-shift` | OPEN | SNumericTypeMethods shiftLeft/shiftRight (v6) 5 | `method_call/numeric.rs:110` | L1,L2 | — |  |
| `METHOD-bigint-toUnsigned` | OPEN | SBigIntMethods.toUnsigned (v6) 5 | `property_call.rs` | L1,L2 | — |  |
| `METHOD-bigint-toUnsignedMod` | OPEN | SBigIntMethods.toUnsignedMod (v6) 15 | `method_call/numeric.rs:208` | L1,L2 | — |  |
| `METHOD-ubigint-toSigned` | OPEN | SUnsignedBigIntMethods.toSigned (v6) 10 | `property_call.rs` | L1,L2 | — |  |
| `METHOD-ubigint-bitwise` | OPEN | SUnsignedBigIntMethods bitwiseOr/And/Xor (v6) 5 | `method_call/unsigned_bigint.rs:40` | L1,L2 | — |  |
| `METHOD-ubigint-shift` | OPEN | SUnsignedBigIntMethods shiftLeft/shiftRight (v6) 5 | `method_call/unsigned_bigint.rs:66,97` | L1,L2 | — |  |
| `METHOD-ubigint-modInverse` | OPEN | SUnsignedBigIntMethods.modInverse (v6) 150 | `method_call/unsigned_bigint.rs:125` | L1,L2 | — |  |
| `METHOD-ubigint-plusMod` | OPEN | SUnsignedBigIntMethods.plusMod (v6) 30 | `method_call/unsigned_bigint.rs:163` | L1,L2 | — |  |
| `METHOD-ubigint-subtractMod` | OPEN | SUnsignedBigIntMethods.subtractMod (v6) 30 | `method_call/unsigned_bigint.rs:183` | L1,L2 | — |  |
| `METHOD-ubigint-multiplyMod` | OPEN | SUnsignedBigIntMethods.multiplyMod (v6) 40 | `method_call/unsigned_bigint.rs:212` | L1,L2 | — |  |
| `METHOD-ubigint-mod` | OPEN | SUnsignedBigIntMethods.mod (v6) 20 | `method_call/unsigned_bigint.rs:230` | L1,L2 | — |  |
| `METHOD-unclaimed-inventory` | OPEN | every SMethod in every type companion not listed above | `method_call/mod.rs fallthrough → EvalError::TypeError` | L1 | — | L1 extractor must list every method Scala can dispatch; each either maps to a row or is proven unreachable/unsupported identically on both sides |
| `METHOD-global-serialize-writer-callbacks` | OPEN | enumeration E042-E047: each SigmaByteWriter callback charge site (putByte/putShort/putInt/putLong/putBytes/putUInt uncharged/unsigned-byte inheritance) | `method_call/global.rs:556-660` | L1,L2 | — | split METHOD-global-serialize into per-callback rows |

## EVAL

| id | state | Scala | Rust | layers | tests | note |
|---|---|---|---|---|---|---|
| `EVAL-const-inline` | OPEN | Constant.costKind FixedCost(5) (values.scala) | `ergo-sigma/src/evaluator/dispatch.rs:321` | L1,L2 | — | candidate: bool_collection_logical_cost.json (20 + 5*n) — annotate to close |
| `EVAL-hasdeserialize-fork` | OPEN | Interpreter.fullReduction: ErgoTree.hasDeserialize → toProposition(inline constants) + EmptyConstants; +4 per constant ref | `ergo-sigma/src/evaluator/dispatch.rs:107-315` | L2 | — | dead-branch deserialize nodes still trigger the fork |
| `EVAL-addtoenv` | OPEN | AddToEnvironment FixedCost(5) per HOF element / per Apply | `ergo-sigma/src/evaluator/opcodes/collection.rs:285` | L2 | — |  |
| `EVAL-numeric-cast` | OPEN | Upcast/Downcast TypeBasedCost: 30 when target SBigInt/SUnsignedBigInt else 10 | `ergo-sigma/src/evaluator/opcodes/cast.rs:16` | L1,L2 | — |  |
| `EVAL-arith-bigint` | OPEN | ArithOp TypeBasedCost: BigInt +/- 20, * / % 25, min/max 10 | `ergo-sigma/src/cost_table.rs:215-242` | L1,L2 | — |  |
| `EVAL-eq-prim` | OPEN | DataValueComparer EQ_Prim = 3 (dispatch embedded) | `ergo-sigma/src/cost_table.rs:246` | L1,L2 | — |  |
| `EVAL-eq-matchtype` | OPEN | DataValueComparer MatchType = 1 | `ergo-sigma/src/cost_table.rs:245` | L1,L2 | — |  |
| `EVAL-eq-tuple` | OPEN | EQ_Tuple = 4 then element recursion | `ergo-sigma/src/cost_table.rs` | L1,L2 | — |  |
| `EVAL-eq-groupelement` | OPEN | EQ_GroupElement = 172 | `ergo-sigma/src/cost_table.rs` | L1,L2 | — |  |
| `EVAL-eq-bigint` | OPEN | EQ_BigInt = 5 (BigInt, UnsignedBigInt) | `ergo-sigma/src/cost_table.rs` | L1,L2 | — |  |
| `EVAL-eq-avltree` | OPEN | EQ_AvlTree = 6 | `ergo-sigma/src/cost_table.rs` | L1,L2 | — |  |
| `EVAL-eq-box` | OPEN | EQ_Box = 6 | `ergo-sigma/src/cost_table.rs` | L1,L2 | — |  |
| `EVAL-eq-option` | OPEN | EQ_Option = 4 then inner recursion on (Some,Some) | `ergo-sigma/src/cost_table.rs` | L1,L2 | — |  |
| `EVAL-eq-preheader` | OPEN | EQ_PreHeader = 4 | `ergo-sigma/src/cost_table.rs` | L1,L2 | — |  |
| `EVAL-eq-header` | OPEN | EQ_Header = 6 | `ergo-sigma/src/cost_table.rs` | L1,L2 | — |  |
| `EVAL-eq-coll-descriptor` | OPEN | EQ_COA_* descriptors: Bool/Byte(15,2,128) Short(15,2,96) Int(15,2,64) Long(15,2,48) BigInt(15,7,5) GroupElement/Box/Header(15,5,1) AvlTree(15,5,2) PreHeader(15,3,1) | `ergo-sigma/src/cost_table.rs:321-374` | L1,L2 | — | SUSPECT divergence: Scala equalCOA_Prim (DataValueComparer.scala:159-176) returns i = items ACTUALLY compared (stops at first mismatch) as the addSeqCost item count; costing.md §6.2 and Rust charge the FULL length. Also String equality uses EQ_COA_Short over len (DataValueComparer.scala:403), not the Coll[Byte] descriptor. Needs JVM vectors with an early mismatch. |
| `EVAL-eq-coll-sigmaprop-descriptor` | OPEN | no Scala descriptor for Coll[SigmaProp] | `ergo-sigma/src/evaluator/cost.rs:250` | L2 | — | Rust keeps (15,5,1) 'pending a vector' — must be proven or removed |
| `EVAL-eq-coll-fallback` | OPEN | equalColls fallback: per-element equalDataValues, stop at first unequal, then EQ_Coll PerItemCost(10,2,1) over compared count | `ergo-sigma/src/evaluator/cost.rs:428-471` | L2 | — |  |
| `EVAL-eq-tokens` | OPEN | Coll[(Coll[Byte],Long)] expansion: MatchType, PerItem(10,2,1), per element EQ_Tuple + 2 MatchType + (15,2,128)@32 + EQ_Prim | `ergo-sigma/src/cost_table.rs:375-395` | L2 | — | finding #16 (token-eq cost) fixed here |
| `EVAL-eq-sigmaboolean` | OPEN | DataValueComparer.equalSigmaBoolean: MatchType per node, EQ_GroupElement per point, DHT short-circuit, conjecture arms throw on mismatch | `ergo-sigma/src/evaluator/cost.rs:6-100` | L2 | — | order-sensitive error behaviour |
| `EVAL-eq-boxcollection` | OPEN | Coll[Box] via lazy carrier: EQ_COA_Box (15,5,1) after MatchType | `ergo-sigma/src/evaluator/cost.rs:179-196` | L2 | — |  |
| `EVAL-max-depth` | N-A | no Scala equivalent (JVM stack) | `ergo-sigma/src/evaluator/types.rs:650` | L2 | — | MAX_EVAL_DEPTH=100 is a Rust guard, not a cost; must be proven unreachable for any tree Scala accepts — tracked outside this ledger |
| `EVAL-avl-cost-height` | OPEN | AvlTree cost height = digest trailing byte; 0 when metadata invalid (BatchAVLVerifier requires fail before rootNodeHeight) | `ergo-sigma/src/evaluator/cost.rs:477-514` | L2 | — | one JVM-blessed contains-on-bad-proof vector exists in avl_scala_oracle_parity.rs — name it |
| `EVAL-deferred-charge-on-exception` | OPEN | enumeration E012-E013: charges deferred/skipped when an exception aborts an operation mid-charge | `unverified` | L2,L3 | — | charged-to-failure value must match on both sides |

## INTERP

| id | state | Scala | Rust | layers | tests | note |
|---|---|---|---|---|---|---|
| `INTERP-init-cost` | OPEN | ErgoInterpreter.interpreterInitCost = 10000 (block units, not votable) | `ergo-validation/src/tx/script/cost.rs:13` | L1,L3,L4 | — | cost_limit_rejects_at_init_cost_charge exists but is Rust-oracled |
| `INTERP-eval-sigmaprop-constant` | OPEN | Interpreter.fullReduction: Eval_SigmaPropConstant FixedCost(50) on the trivial path, then .toBlockCost | `ergo-sigma/src/reduce.rs:10,292` | L2,L4 | — | P2PK path; L4 covers it massively but no tracked independent vector names the row |
| `INTERP-deser-subst` | OPEN | reductionWithDeserialize: ergoTree.bytes.length * CostPerTreeByte(2) added to initCost, checked against costLimit | `ergo-sigma/src/reduce.rs:14,242` | L2,L3 | — | documented coverage gap: reduce oracle bypasses it (manifest.toml #6); needs the L2 verify surface |
| `INTERP-crypto-dlog` | OPEN | estimateCryptoVerifyCost ProveDlog = ParseChallenge 10 + ComputeCommitments_Schnorr 3400 + ToBytes_Schnorr 570 = 3980 | `ergo-sigma/src/crypto_cost.rs:31` | L1,L2 | — |  |
| `INTERP-crypto-dht` | OPEN | ProveDHTuple = 10 + 6450 + 680 = 7140 | `ergo-sigma/src/crypto_cost.rs:34` | L1,L2 | — |  |
| `INTERP-crypto-conjunction` | OPEN | CAND/COR: ToBytes_Conjunction 15 + children | `ergo-sigma/src/crypto_cost.rs:41` | L1,L2 | — |  |
| `INTERP-crypto-threshold` | OPEN | Interpreter.scala:580-587 CTHRESHOLD: nCoefs = n - k (NO max(..,1)); ParsePolynomial.cost(nCoefs) + EvaluatePolynomial.cost(nCoefs) * n + ToBytes_ProofTreeConjecture 15 + children | `ergo-sigma/src/crypto_cost.rs:56 (parse_chunks = max(n_coefs, 1))` | L1,L2 | — | SUSPECT divergence: for k == n (nCoefs = 0, reachable via a serialized CTHRESHOLD constant) Scala charges base-only (10 and 3*n), Rust charges one chunk (20 and 6*n). Needs a JVM vector; open DIVERGENT if confirmed. |
| `INTERP-crypto-trunc` | CLOSED | addCryptoCost: estimateCryptoVerifyCost(sb).toBlockCost then addCostChecked(baseCost, cryptoCost, costLimit) | `ergo-sigma/src/reduce.rs:314-327` | L2,L3 | `ergo-validation::it::cost_crypto_truncation::conjunction_two_inputs_block_cost_matches_scala`<br>`ergo-validation::it::cost_crypto_truncation::conjunction_tx_at_exact_scala_limit_accepts` | JVM ErgoTransaction.validateStateful (ergo-core/ergo-wallet/sigma-state 6.0.2): multi_input_conjunction_cost.json, TX-A 15704 and TX-B 22916 block units; recorded C-1/C/C+1 verdicts pass after per-input crypto truncation. Fix: task 0.1 on feat/jit-cost-conformance; PR unavailable (owner forbids pushing). |
| `INTERP-costlimit-op` | OPEN | CostAccumulator.scala:55 add first, throw iff accumulatedCost > limit (equality allowed; counter already incremented on throw); Interpreter.addCostChecked same operator | `ergo-primitives/src/cost.rs:282-294` | L3 | — | Rust compares in JIT units against limit*10; Scala compares block units — equivalence must be proven per ROUND-snap and INTERP-crypto-trunc |
| `INTERP-jitcost-bounds` | OPEN | JitCost.+ Math.addExact; fromBlockCost Math.multiplyExact(blockCost,10); Int.MaxValue bound | `ergo-primitives/src/cost.rs:53-162` | L1 | — | Rust returns typed Overflow instead of throwing; unreachable from honest input (pin test exists, Rust-oracled) |
| `INTERP-toblockcost` | OPEN | JitCost.toBlockCost = value / 10 (Int division) | `ergo-primitives/src/cost.rs:137` | L1,L3 | — |  |
| `INTERP-embedded-script-deser` | OPEN | enumeration I003: measured deserialization cost of embedded scripts (DeserializeContext/Register) beyond the tree-byte init cost | `ergo-sigma/src/reduce.rs / dispatch.rs` | L2 | — |  |

## ROUND

| id | state | Scala | Rust | layers | tests | note |
|---|---|---|---|---|---|---|
| `ROUND-snap-per-input` | OPEN | Interpreter.verify: per-input eval JitCost .toBlockCost before crypto cost | `ergo-primitives/src/cost.rs:312 + ergo-sigma/src/reduce.rs:314` | L2,L3 | — | Rust snap drops delta%10 of the accumulator since baseline; must equal Scala's per-input truncation for every input sequence |
| `ROUND-crypto-per-input` | CLOSED | addCryptoCost .toBlockCost per input | `ergo-sigma/src/reduce.rs:320-327` | L3 | `ergo-validation::it::cost_crypto_truncation::conjunction_two_inputs_block_cost_matches_scala`<br>`ergo-validation::it::cost_crypto_truncation::conjunction_tx_at_exact_scala_limit_accepts` | JVM ErgoTransaction.validateStateful (ergo-core/ergo-wallet/sigma-state 6.0.2): multi_input_conjunction_cost.json, TX-A 15704 and TX-B 22916 block units; recorded C-1/C/C+1 verdicts pass after per-input crypto truncation. Fix: task 0.1 on feat/jit-cost-conformance; PR unavailable (owner forbids pushing). |
| `ROUND-perItem-chunking` | OPEN | PerItemCost.cost(n) = base + perChunk * chunks, chunks = (n-1)/chunkSize + 1 with JVM truncation toward zero; n=0 with chunkSize=1 gives 0 chunks | `ergo-primitives/src/cost.rs:195-222` | L1,L2 | — | per_item_zero_items_chunk_size_one_uses_zero_chunks is Rust-oracled; needs a JVM vector at n=0 for chunk_size 1 and >=2 |

## ORDER

| id | state | Scala | Rust | layers | tests | note |
|---|---|---|---|---|---|---|
| `ORDER-init-token` | OPEN | ErgoTransaction.validateStateful: initialCost (interpreter+inputs+dataInputs+outputs) checked first; token cost added later in the chain | `ergo-validation/src/tx/script/cost.rs:46 (single up-front add incl. tokens)` | L3,L5 | — | obligation: verdict unchanged for every limit value, including limits between init and init+token |
| `ORDER-pre-v3-upcast` | OPEN | DeserializationSigmaBuilder.applyUpcast inserts Upcast at parse time (charged mid-eval) | `ergo-sigma/src/evaluator/opcodes/cast.rs:36-118 (charged after both operands)` | L2,L3 | — | totals identical on success; prove identical verdict at the limit |
| `ORDER-blockvalue-valdef` | OPEN | BlockValue: addFixedCost(AddToEnvironment) wraps only the env update, after rhs eval | `ergo-sigma/src/evaluator/opcodes/binding.rs:81-100` | L2,L3 | — |  |
| `ORDER-constplaceholder` | OPEN | ConstantPlaceholder cost charged before index bounds check | `ergo-sigma/src/evaluator/opcodes/binding.rs:29-40` | L2 | — |  |
| `ORDER-hof-charge` | OPEN | HOFs: collection eval → PerItem charge over length → lambda → AddToEnv per element → body | `ergo-sigma/src/evaluator/opcodes/collection.rs:265-369` | L2,L3 | — |  |
| `ORDER-comparison-charge` | OPEN | LT/LE/GT/GE cost charged after both operands | `ergo-sigma/src/evaluator/opcodes/comparison.rs:18-39` | L2,L3 | — |  |
| `ORDER-bitop-charge-then-reject` | OPEN | BitOp family: costKind Fixed(1) accumulated, then Value.eval default throws | `ergo-sigma/src/evaluator/opcodes/errors.rs:42-82` | L2,L3 | — | charged-to-failure value observable on both sides |
| `ORDER-crypto-before-verify` | OPEN | crypto cost added before sigma-proof verification runs | `ergo-sigma/src/reduce.rs:320-330` | L3 | — | cost-limit failure must precede a proof failure at the limit |

## LIMIT

| id | state | Scala | Rust | layers | tests | note |
|---|---|---|---|---|---|---|
| `LIMIT-tx-start` | OPEN | validateStateful: maxCost >= initialCost + accumulatedCost (bsBlockTransactionsCost) | `ergo-validation/src/tx/mod.rs:144-151 (init add into fresh per-tx accumulator)` | L3,L5 | — | Scala includes the block's running total; Rust checks per-tx then sums — see BLOCK-accum-equiv |
| `LIMIT-per-input` | OPEN | ErgoTransaction.scala:135-136: each input verified with costLimit = maxCost - currentTxCost (REMAINING budget) and initCost = 0; CostLimitException iff cost > limit | `ergo-primitives/src/cost.rs:282-294 per add (single tx-wide accumulator vs cap)` | L3 | — | Rust: running total vs cap; Scala: per-input cost vs remaining budget — equal in block units by monotonicity; JIT remainders break it until INTERP-crypto-trunc is fixed |
| `LIMIT-block-sum` | OPEN | ErgoState.execTransactions: per-tx validateStateful(accumulatedCost) with bsBlockTransactionsCost (ValidationRules.scala:174); UtxoState.scala:84 delegates; equality allowed (maxCost >= cost) | `ergo-validation/src/block/validate.rs:339,681` | L5,L6 | — | operator and unit (block) must match; Scala anchor to be pinned by enumeration |

## TX

| id | state | Scala | Rust | layers | tests | note |
|---|---|---|---|---|---|---|
| `TX-init-formula` | OPEN | initialCost = interpreterInitCost + inputs*inputCost + dataInputs*dataInputCost + outputs*outputCost (addExact/multiplyExact) | `ergo-validation/src/tx/script/cost.rs:22-60` | L3,L4 | — | cost_total_oracle_* prove totals for 5 txs but do not isolate the formula; L4 per-input breakdown closes it |
| `TX-token-cost` | OPEN | token cost = (in entries + out entries + in distinct ids + out distinct ids) * tokenAccessCost | `ergo-validation/src/tx/script/cost.rs:121-144` | L3,L4 | — | counting rule must be pinned to the Scala anchor by the enumeration |
| `TX-storage-rent` | OPEN | StorageContractCost = 50 charged instead of script when rent conditions hold; recoverWith → normal verify on failure | `ergo-validation/src/tx/script/mod.rs:216-264` | L2,L3,L4 | — | rent-eligible fixtures from mainnet (rent branch has corpora) |
| `TX-scripts-skipped-pairing` | OPEN | below checkpoint (scripts not verified) → no cost charged | `ergo-validation/src/tx/mod.rs:210-227` | L4 | — |  |
| `TX-voted-params` | OPEN | Parameters ids 4 maxBlockCost, 5 tokenAccessCost, 6 inputCost, 7 dataInputCost, 8 outputCost from epoch extension | `ergo-validation/src/active_params/mod.rs` | L4 | — | cost_total_oracle_epoch_1499136_uses_voted_params is JVM-backed for one epoch — name it once it carries the ledger id |
| `TX-accumulator-shared` | OPEN | all inputs of a tx accumulate into one running cost | `ergo-validation/src/tx/script/mod.rs:89-324` | L3 | — |  |

## BLOCK

| id | state | Scala | Rust | layers | tests | note |
|---|---|---|---|---|---|---|
| `BLOCK-per-tx-cap` | OPEN | each tx validated with maxCost = maxBlockCost and accumulatedCost = block running total | `ergo-validation/src/block/validate.rs:311,611 (fresh accumulator, cap = full block limit)` | L5 | — |  |
| `BLOCK-accum-equiv` | OPEN | running accumulatedCost passed into every validateStateful | `fresh per-tx accumulator + deferred sum (validate.rs:339,681)` | L3,L5 | — | prove: for every block and every limit, Scala's prefix check and Rust's (per-tx ≤ cap ∧ sum ≤ cap) yield the same verdict; monotone non-negative costs make them equal in block units, but JIT-unit remainders break it until INTERP-crypto-trunc is fixed |
| `BLOCK-sum-op` | OPEN | reject iff accumulated block cost > maxBlockCost (equality allowed) — ErgoTransaction.scala:377,394 via ErgoState.execTransactions | `ergo-validation/src/block/validate.rs:339,681` | L5,L6 | — |  |
| `BLOCK-parallel-equiv` | OPEN | n/a (Scala is sequential) | `ergo-validation/src/block/validate.rs:748 validate_full_block_parallel_with_costs` | L5 | — | parallel validator must match sequential (sum, verdict, failure_class) on every fixture |
| `BLOCK-overflow` | OPEN | addExact/multiplyExact throw ArithmeticException → block invalid | `typed JitCostOverflow / saturating init arithmetic` | L5 | — | unreachable from honest input; prove both sides reject (not accept) if ever reached |
| `BLOCK-rejection-state-unchanged` | OPEN | failed applyModifier leaves state unchanged | `ergo-state apply path` | L6 | — | devnet before/after state commitments |
| `BLOCK-param-voting` | OPEN | enumeration B009-B012 / G024-G025: Parameters.scala:168-176 step max(1,current/100), min 16384 for maxBlockCost, update only on approved vote; fork vote increments block version | `ergo-validation/src/voting/` | L4,L5 | — | cost parameters reach the accounting through this path; L4 boundary ranges exercise it |
| `BLOCK-overflow-fixture` | OPEN | addExact/multiplyExact ArithmeticException → Try failure → rollback (UtxoState.scala:139,209) | `typed overflow` | L5 | — | explicit fixture required (final review) |

## VERSION

| id | state | Scala | Rust | layers | tests | note |
|---|---|---|---|---|---|---|
| `VERSION-jit-activation` | OPEN | Header.scala:142 Interpreter50Version = 3: JIT costing active from BLOCK version 3 (v5.0), activatedScriptVersion 2; HardeningVersion = 2 is the 4.0 hard fork; Interpreter60Version = 4 | `ergo-validation/src/context.rs:164 activated_script_version` | L4 | — | v1 blocks: confirm whether Scala re-verifies with JIT or skips (checkpoint) — the ledger must state which |
| `VERSION-pre-v3-upcast` | OPEN | applyUpcast only for ErgoTree version < 3 | `ergo-sigma/src/evaluator/opcodes/cast.rs:75` | L2,L4 | — |  |
| `VERSION-v3-bool-root` | OPEN | v3/6.0 trees allow SBoolean root; implicit BoolToSigmaProp coercion costed by evaluator | `ergo-sigma/src/reduce.rs:25-47` | L2 | — |  |
| `VERSION-v6-method-gate` | OPEN | _v6Methods require activatedScriptVersion >= 3 (EIP-50) | `ergo-sigma/src/evaluator/opcodes/method_call/mod.rs:172-190` | L2 | — | cost of a gated method on a pre-v6 context: rejection with what charged-to-failure value? |
| `VERSION-selfboxindex-bug` | OPEN | selfBoxIndex returns -1 when activatedScriptVersion < 2 (sigmastate#603) | `property_call.rs` | L2 | — | bug-compatible row |
| `VERSION-tree-version-gate` | OPEN | tree version > activated within supported versions → REJECT; future-version bypass only when both activated and tree versions exceed the supported maximum (checkSoftForkCondition / trySoftForkable) | `PR #331 activated-version gate` | L4 | — | three fixtures needed: rejection, future-version bypass, recognized validation-exception; pin the cost charged in each |
| `VERSION-hardening-creation-height` | N-A | blockVersion <= HardeningVersion changes maxCreationHeightInInputs (not a cost) | `n/a` | L4 | — | listed for completeness of validateStateful branches; no cost effect |
| `VERSION-v6-lazy-defaults` | OPEN | v3-tree lazy default arguments can avoid charging an unused expression (codex enumeration note) | `unverified` | L2 | — | from the blind enumeration; must be located in Scala source and mirrored or proven unreachable |
| `VERSION-subst-retention` | OPEN | enumeration G002: activation-dependent retention of substituted constants after deserialization | `unverified` | L2 | — |  |
| `VERSION-branches-G007-G020` | OPEN | enumeration G007-G020: versioned execution branches that change charged execution (to be split into one row each in Task 1.3) | `various` | L2 | — | placeholder group row; Task 1.3 must replace it with individual rows |
