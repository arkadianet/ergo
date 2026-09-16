## Scope and notation

This inventory uses only the Scala source in the two supplied directories. No Rust source or external documentation was consulted.

**Costs are in JIT units unless marked `BC`** (block-cost units). A declaration is not necessarily an executable charge: unsupported/frontend nodes are included explicitly.

- `F(x)` = `FixedCost(JitCost(x))`.
- `P(b,p,k;n)` = `PerItemCost(b,p,k).cost(n)`.
- **Exact formula:** `b + p * ((n - 1) / k + 1)`, with Scala integer division. For `n=0`, this charges one chunk when `k>1`, but zero chunks when `k=1`.
- `T3` = `ergoTreeVersion >= 3`.
- `A6` = `activatedScriptVersion >= 3`.
- `J` = `activatedScriptVersion >= 2`.
- `—` = no additional version condition at that declaration/site; surrounding interpreter/version checks still apply.
- Method costs exclude receiver/argument evaluation and the separate `MethodCall` overhead.

### File-prefix key

Paths in the tables expand using these prefixes:

| Prefix | Directory |
|---|---|
| `D` | [sigmastate data Scala sources](/home/rkadias/coding/reference/ergo-core/sigmastate-interpreter-v6.0.2/data/shared/src/main/scala) |
| `I` | [sigmastate interpreter Scala sources](/home/rkadias/coding/reference/ergo-core/sigmastate-interpreter-v6.0.2/interpreter/shared/src/main/scala) |
| `C` | [sigmastate core Scala sources](/home/rkadias/coding/reference/ergo-core/sigmastate-interpreter-v6.0.2/core/shared/src/main/scala) |
| `EC` | [Ergo core Scala sources](/home/rkadias/coding/reference/ergo-core/ergo/ergo-core/src/main/scala) |
| `EW` | [Ergo wallet Scala sources](/home/rkadias/coding/reference/ergo-core/ergo/ergo-wallet/src/main/scala) |
| `EN` | [Ergo node Scala sources](/home/rkadias/coding/reference/ergo-core/ergo/src/main/scala) |

Within category 1, `values.scala`, `trees.scala`, and `transformers.scala` mean `D/sigma/ast/…`. Within category 2, `methods.scala` means `D/sigma/ast/methods.scala`.

## 1. AST/opcode `costKind` declarations

| id | category | Scala file:line | what is charged / checked (formula or constant) | version/activation gating | notes |
|---|---|---|---|---|---|
| A001 | 1 | values.scala:380 | `Constant`: F(5) | — | Ordinary evaluated constant. |
| A002 | 1 | values.scala:421 | `ConstantPlaceholder`: F(1) | — | Constant-pool reference. |
| A003 | 1 | values.scala:444 | `TaggedVariable`: F(1) | — | Declaration; no concrete evaluator override here. |
| A004 | 1 | values.scala:712 | `GroupGenerator`: F(10) | — | Overrides ordinary constant evaluation. |
| A005 | 1 | values.scala:747 | `TrueLeaf`: `Constant.costKind` = F(5) | — | Boolean constant. |
| A006 | 1 | values.scala:758 | `FalseLeaf`: `Constant.costKind` = F(5) | — | Boolean constant. |
| A007 | 1 | values.scala:815 | `Tuple`: F(15) | — | Plus evaluated components. |
| A008 | 1 | values.scala:878 | `ConcreteCollection`: F(20) | — | Plus evaluated elements. |
| A009 | 1 | values.scala:890 | `ConcreteCollectionBooleanConstant`: F(20) | — | Inherits collection descriptor. |
| A010 | 1 | values.scala:935 | `ValDef`: `notSupportedError` | — | Binding is handled by `BlockValue`. |
| A011 | 1 | values.scala:943 | `FunDef`: `notSupportedError` | — | Declaration/extractor, not standalone charge. |
| A012 | 1 | values.scala:971 | `ValUse`: F(5) | — | Environment lookup. |
| A013 | 1 | values.scala:1013 | `BlockValue`: P(1,1,10; number of bindings) | — | Additional environment charge per binding. |
| A014 | 1 | values.scala:1070 | `FuncValue`: F(5) | — | Creates closure; application also charges binding. |
| A015 | 1 | values.scala:1091 | `Block`: `notSupportedError` | — | Frontend structure. |
| A016 | 1 | values.scala:1121 | `ZKProofBlock`: `notSupportedError` | — | Frontend structure. |
| A017 | 1 | values.scala:1161 | `ValNode`: `notSupportedError` | — | Frontend named binding. |
| A018 | 1 | values.scala:1186 | `Select`: `notSupportedError` | — | Frontend selection. |
| A019 | 1 | values.scala:1201 | `Ident`: `notSupportedError` | — | Frontend identifier. |
| A020 | 1 | values.scala:1253 | `Apply`: F(30) | — | Its opcode is `FuncApplyCode`, line 1249. |
| A021 | 1 | values.scala:1276 | `ApplyTypes`: `notSupportedError` | — | Frontend type application. |
| A022 | 1 | values.scala:1295 | `MethodCallLike`: `notSupportedError` | — | Frontend unresolved method call. |
| A023 | 1 | values.scala:1371 | `MethodCall`: F(4) | — | Dispatch overhead, not method body cost. |
| A024 | 1 | values.scala:1391 | `PropertyCall`: F(4) | — | Property-call descriptor. |
| A025 | 1 | values.scala:1416 | `Lambda`: `notSupportedError` | — | Frontend lambda; lowered to `FuncValue`. |
| A026 | 1 | values.scala:1439 | `MinerPubkey`: F(20) | — | Context field. |
| A027 | 1 | values.scala:1453 | `Height`: F(26) | — | Context field. |
| A028 | 1 | values.scala:1466 | `Inputs`: F(10) | — | Context field. |
| A029 | 1 | values.scala:1480 | `Outputs`: F(10) | — | Context field. |
| A030 | 1 | values.scala:1495 | `LastBlockUtxoRootHash`: F(15) | — | Context field. |
| A031 | 1 | values.scala:1509 | `Self`: F(10) | — | Context field. |
| A032 | 1 | values.scala:1525 | `Context`: F(1) | — | Context object. |
| A033 | 1 | values.scala:1542 | `Global`: F(5) | — | Global DSL object. |
| A034 | 1 | transformers.scala:52 | `MapCollection`: P(20,1,10; input length) | — | Mapping function charged separately on invocation. |
| A035 | 1 | transformers.scala:74 | `Append`: P(20,2,100; left length + right length) | — | Charge before concatenation. |
| A036 | 1 | transformers.scala:106 | `Slice`: P(10,2,100; `max(0,until-from)`) | — | Uses requested interval, not actual result length; subtraction is ordinary Int arithmetic. |
| A037 | 1 | transformers.scala:134 | `Filter`: P(20,1,10; input length) | — | Predicate charges additional. |
| A038 | 1 | transformers.scala:170 | `Exists`: P(3,1,10; input length) | — | Full input length for overhead, even if predicate short-circuits. |
| A039 | 1 | transformers.scala:197 | `ForAll`: P(3,1,10; input length) | — | Full input length for overhead. |
| A040 | 1 | transformers.scala:236 | `Fold`: P(3,1,10; input length) | — | Fold function charges additional. |
| A041 | 1 | transformers.scala:285 | `ByIndex`: F(30) | T3 changes default evaluation | See G003. |
| A042 | 1 | transformers.scala:314 | `SelectField`: F(10) | — | Tuple component. |
| A043 | 1 | transformers.scala:328 | `SigmaPropIsProven`: `notSupportedError` | — | Frontend-only construct. |
| A044 | 1 | transformers.scala:349 | `SigmaPropBytes`: P(35,6,1; SigmaBoolean node count) | — | Counts proposition nodes, not serialized bytes. |
| A045 | 1 | transformers.scala:373 | `SizeOf`: F(14) | — | Collection size. |
| A046 | 1 | transformers.scala:394 | `ExtractAmount`: F(8) | — | Box value. |
| A047 | 1 | transformers.scala:420 | `ExtractScriptBytes`: F(10) | — | Box guarding-script bytes. |
| A048 | 1 | transformers.scala:440 | `ExtractBytes`: F(12) | — | Full box bytes. |
| A049 | 1 | transformers.scala:460 | `ExtractBytesWithNoRef`: F(12) | — | Box bytes without reference. |
| A050 | 1 | transformers.scala:479 | `ExtractId`: F(12) | — | Box ID. |
| A051 | 1 | transformers.scala:500 | `ExtractRegisterAs`: F(50) | — | Typed register extraction. |
| A052 | 1 | transformers.scala:527 | `ExtractCreationInfo`: F(16) | — | Creation-height/reference tuple. |
| A053 | 1 | transformers.scala:558 | `DeserializeContext`: P(1,10,128; bytes) | — | Declared descriptor; substitution path uses measured BC charges instead. |
| A054 | 1 | transformers.scala:571 | `DeserializeRegister`: P(1,10,128; bytes) | — | Same distinction as A053. |
| A055 | 1 | transformers.scala:589 | `GetVar`: F(10) | — | Typed extension-variable access. |
| A056 | 1 | transformers.scala:611 | `OptionGet`: F(15) | — | Charged before extracting option value. |
| A057 | 1 | transformers.scala:649 | `OptionGetOrElse`: F(20) | T3 changes default evaluation | See G004. |
| A058 | 1 | transformers.scala:667 | `OptionIsDefined`: F(10) | — | Option predicate. |
| A059 | 1 | trees.scala:55 | `BoolToSigmaProp`: F(15) | J changes semantics | See G009. |
| A060 | 1 | trees.scala:73 | `CreateProveDlog`: F(10) | — | Proposition construction, not proof verification. |
| A061 | 1 | trees.scala:89 | `CreateAvlTree`: `notSupportedError` | — | No evaluator implementation here. |
| A062 | 1 | trees.scala:114 | `CreateProveDHTuple`: F(20) | — | Proposition construction. |
| A063 | 1 | trees.scala:149 | `SigmaAnd`: P(10,2,1; child count) | — | Plus child evaluation. |
| A064 | 1 | trees.scala:180 | `SigmaOr`: P(10,2,1; child count) | — | Plus child evaluation. |
| A065 | 1 | trees.scala:222 | `OR`: P(5,5,64; examined Boolean count) | — | Count returned by short-circuit loop; charged afterward. |
| A066 | 1 | trees.scala:253 | `XorOf`: P(20,5,32; input length) | — | Entire collection. |
| A067 | 1 | trees.scala:292 | `AND`: P(10,5,32; examined Boolean count) | — | Short-circuit loop count. |
| A068 | 1 | trees.scala:328 | `AtLeast`: P(20,3,5; proposition count) | — | Charge uses original proposition collection length. |
| A069 | 1 | trees.scala:415,418 | `Upcast`: `NumericCastCostKind` | T3 extends supported conversions | Target BigInt/UnsignedBigInt 30; other targets 10. |
| A070 | 1 | trees.scala:415,442 | `Downcast`: `NumericCastCostKind` | T3 extends supported conversions | Same target-based pricing. |
| A071 | 1 | trees.scala:466 | `LongToByteArray`: F(17) | — | Numeric conversion. |
| A072 | 1 | trees.scala:486 | `ByteArrayToLong`: F(16) | — | Numeric conversion. |
| A073 | 1 | trees.scala:506 | `ByteArrayToBigInt`: F(30) | — | Numeric conversion. |
| A074 | 1 | trees.scala:530 | `DecodePoint`: F(300) | — | Group-element decoding. |
| A075 | 1 | trees.scala:582 | `CalcBlake2b256`: P(20,7,128; byte length) | — | Hash input bytes. |
| A076 | 1 | trees.scala:604 | `CalcSha256`: P(80,8,64; byte length) | — | Hash input bytes. |
| A077 | 1 | trees.scala:655 | `SubstConstants`: P(100,100,1; original constant count) | J/T3 affect substitution implementation | Uses returned `nConstants`, not number of replacements. |
| A078 | 1 | trees.scala:752 | `ArithOp.Plus`: TypeBasedCost, BigInt 20; otherwise 15 | — | Type supplied by selected arithmetic implementation. |
| A079 | 1 | trees.scala:767 | `ArithOp.Minus`: BigInt 20; otherwise 15 | — | TypeBasedCost. |
| A080 | 1 | trees.scala:782 | `ArithOp.Multiply`: BigInt 25; otherwise 15 | — | TypeBasedCost. |
| A081 | 1 | trees.scala:797 | `ArithOp.Division`: BigInt 25; otherwise 15 | — | TypeBasedCost. |
| A082 | 1 | trees.scala:814 | `ArithOp.Modulo`: BigInt 25; otherwise 15 | — | TypeBasedCost. |
| A083 | 1 | trees.scala:829 | `ArithOp.Min`: BigInt 10; otherwise 5 | — | TypeBasedCost. |
| A084 | 1 | trees.scala:844 | `ArithOp.Max`: BigInt 10; otherwise 5 | — | TypeBasedCost. |
| A085 | 1 | trees.scala:894 | `Negation`: F(30) | — | Fixed, not arithmetic-by-type pricing. |
| A086 | 1 | trees.scala:906 | `BitInversion`: `notSupportedError` | — | Distinct from v6 numeric method. |
| A087 | 1 | trees.scala:926 | `BitOp.BitOr`: F(1) | — | Placeholder declaration; `BitOp` lacks evaluator implementation. |
| A088 | 1 | trees.scala:929 | `BitOp.BitAnd`: F(1) | — | Same limitation. |
| A089 | 1 | trees.scala:932 | `BitOp.BitXor`: F(1) | — | Same limitation. |
| A090 | 1 | trees.scala:935 | `BitOp.BitShiftRight`: F(1) | — | Same limitation. |
| A091 | 1 | trees.scala:938 | `BitOp.BitShiftLeft`: F(1) | — | Same limitation. |
| A092 | 1 | trees.scala:941 | `BitOp.BitShiftRightZeroed`: F(1) | — | Same limitation. |
| A093 | 1 | trees.scala:962 | `ModQ`: F(1) | — | Placeholder; no evaluator implementation. |
| A094 | 1 | trees.scala:973,982 | `ModQArithOp.PlusModQ`: inherited F(1) | — | Placeholder; distinct from unsigned modular methods. |
| A095 | 1 | trees.scala:973,986 | `ModQArithOp.MinusModQ`: inherited F(1) | — | Same limitation. |
| A096 | 1 | trees.scala:1016 | `Xor`: P(10,2,128; `min(left.length,right.length)`) | — | `xorWithCosting` applies charge. |
| A097 | 1 | trees.scala:1046 | `Exponentiate`: F(900) | — | Group exponentiation. |
| A098 | 1 | trees.scala:1067 | `MultiplyGroup`: F(40) | — | Group multiplication. |
| A099 | 1 | trees.scala:1106 | `LT`: TypeBasedCost, 20 for every branch | — | BigInt branch also 20. |
| A100 | 1 | trees.scala:1133 | `LE`: TypeBasedCost, 20 | — | Same. |
| A101 | 1 | trees.scala:1160 | `GT`: TypeBasedCost, 20 | — | Same. |
| A102 | 1 | trees.scala:1187 | `GE`: TypeBasedCost, 20 | — | Same. |
| A103 | 1 | trees.scala:1214 | `EQ`: DynamicCost | — | Actual charges in `DataValueComparer`. |
| A104 | 1 | trees.scala:1234 | `NEQ`: DynamicCost | — | Same equality calculation, negated result. |
| A105 | 1 | trees.scala:1257 | `BinOr`: F(20) | — | Boolean short-circuit affects RHS charges. |
| A106 | 1 | trees.scala:1280 | `BinAnd`: F(20) | — | Boolean short-circuit affects RHS charges. |
| A107 | 1 | trees.scala:1300 | `BinXor`: F(20) | — | Both operands. |
| A108 | 1 | trees.scala:1336 | `TreeLookup`: `notSupportedError` | — | Distinct from AVL method implementations. |
| A109 | 1 | trees.scala:1373 | `If`: F(10) | — | Only selected branch evaluated. |
| A110 | 1 | trees.scala:1391 | `LogicalNot`: F(15) | — | Boolean negation. |

Abstract declarations in `ValueCompanion`, `FixedCostValueCompanion`, `PerItemCostValueCompanion`, and `ArithOpCompanion` impose descriptor types; they add no separate charge.

## 2. Every method descriptor

The numeric-family rows below enumerate inherited methods for **each of `SByteMethods`, `SShortMethods`, `SIntMethods`, `SLongMethods`, `SBigIntMethods`, and `SUnsignedBigIntMethods`**. The copying/association sites are `methods.scala:237` and `:243`; the unsigned companion itself is T3-only.

| id | category | Scala file:line | what is charged / checked (formula or constant) | version/activation gating | notes |
|---|---|---|---|---|---|
| M001 | 2 | methods.scala:288 | Numeric family `.toByte`: `costKind=null`; `costOfNumericCast` gives 10 | Unsigned receiver T3 | Compiler cast mapping/custom cost metadata. |
| M002 | 2 | methods.scala:292 | Numeric family `.toShort`: null; target cost 10 | Unsigned receiver T3 | Same. |
| M003 | 2 | methods.scala:296 | Numeric family `.toInt`: null; target cost 10 | Unsigned receiver T3 | Same. |
| M004 | 2 | methods.scala:300 | Numeric family `.toLong`: null; target cost 10 | Unsigned receiver T3 | Same. |
| M005 | 2 | methods.scala:304 | Numeric family `.toBigInt`: null; target cost 30 | Unsigned receiver T3 | Same. |
| M006 | 2 | methods.scala:311 | Numeric family `.toBytes`: F(5) | Unsigned receiver T3 | Fixed regardless of numeric width. |
| M007 | 2 | methods.scala:334 | Numeric family `.toBits`: F(5) | Unsigned receiver T3 | Fixed regardless of numeric width. |
| M008 | 2 | methods.scala:355 | Numeric family `.bitwiseInverse`: F(5) | T3 | Method implementation, not A086. |
| M009 | 2 | methods.scala:370 | Numeric family `.bitwiseOr`: F(5) | T3 | Method implementation, not A087. |
| M010 | 2 | methods.scala:387 | Numeric family `.bitwiseAnd`: F(5) | T3 | Method implementation. |
| M011 | 2 | methods.scala:404 | Numeric family `.bitwiseXor`: F(5) | T3 | Method implementation. |
| M012 | 2 | methods.scala:421 | Numeric family `.shiftLeft`: F(5) | T3 | Method implementation. |
| M013 | 2 | methods.scala:441 | Numeric family `.shiftRight`: F(5) | T3 | Method implementation. |
| M014 | 2 | methods.scala:546 | BigInt `.toUnsigned`: F(5) | T3 | Negative input can throw after charge. |
| M015 | 2 | methods.scala:553 | BigInt `.toUnsignedMod`: F(15) | T3 | Modular conversion. |
| M016 | 2 | methods.scala:576 | UnsignedBigInt `.modInverse`: F(150) | T3 | Additional unsigned method. |
| M017 | 2 | methods.scala:585 | UnsignedBigInt `.plusMod`: F(30) | T3 | Descriptor name accidentally says `ModInverseMethodCall`; amount is 30. |
| M018 | 2 | methods.scala:591 | UnsignedBigInt `.subtractMod`: F(30) | T3 | — |
| M019 | 2 | methods.scala:597 | UnsignedBigInt `.multiplyMod`: F(40) | T3 | — |
| M020 | 2 | methods.scala:603 | UnsignedBigInt `.mod`: F(20) | T3 | — |
| M021 | 2 | methods.scala:609 | UnsignedBigInt `.toSigned`: F(10) | T3 | — |
| M022 | 2 | methods.scala:642 | GroupElement `.getEncoded`: F(250) | — | Serialization/wrapping. |
| M023 | 2 | methods.scala:647 | GroupElement `.exp`: F(900) | — | `Exponentiate.costKind`. |
| M024 | 2 | methods.scala:656 | GroupElement `.expUnsigned`: F(900) | T3 | Same exponentiation descriptor. |
| M025 | 2 | methods.scala:662 | GroupElement `.multiply`: F(40) | — | `MultiplyGroup.costKind`. |
| M026 | 2 | methods.scala:672 | GroupElement `.negate`: F(45) | — | — |
| M027 | 2 | methods.scala:703 | SigmaProp `.propBytes`: P(35,6,1; proposition nodes) | — | Lowering metadata points to `SigmaPropBytes`. |
| M028 | 2 | methods.scala:707 | SigmaProp `.isProven`: `costKind=null` | Frontend only | Not a zero-cost executable proof verifier. |
| M029 | 2 | methods.scala:750 | Option `.isDefined`: F(10) | — | — |
| M030 | 2 | methods.scala:758 | Option `.get`: F(15) | — | — |
| M031 | 2 | methods.scala:765 | Option `.getOrElse`: F(20) | — | AST lazy-default change applies when lowered to A057. |
| M032 | 2 | methods.scala:775 | Option `.map`: F(20) | — | Closure invocation charges additional when present. |
| M033 | 2 | methods.scala:784 | Option `.filter`: F(20) | — | Predicate charges additional when present. |
| M034 | 2 | methods.scala:821 | Coll `.size`: F(14) | — | — |
| M035 | 2 | methods.scala:824 | Coll `.getOrElse`: DynamicCost → F(30) at :840 | — | Actual direct method-call arguments are evaluated eagerly. |
| M036 | 2 | methods.scala:846 | Coll `.map`: P(20,1,10; receiver length) | — | Explicit charge at :865. |
| M037 | 2 | methods.scala:869 | Coll `.exists`: P(3,1,10; receiver length) | — | AST lowering; predicate charges additional. |
| M038 | 2 | methods.scala:880 | Coll `.fold`: P(3,1,10; receiver length) | — | AST lowering. |
| M039 | 2 | methods.scala:891 | Coll `.forall`: P(3,1,10; receiver length) | — | AST lowering. |
| M040 | 2 | methods.scala:903 | Coll `.slice`: P(10,2,100; requested interval length) | — | AST lowering. |
| M041 | 2 | methods.scala:919 | Coll `.filter`: P(20,1,10; receiver length) | — | AST lowering. |
| M042 | 2 | methods.scala:931 | Coll `.append`: P(20,2,100; summed lengths) | — | AST lowering. |
| M043 | 2 | methods.scala:940 | Coll `.apply`: F(30) | — | `ByIndex.costKind`. |
| M044 | 2 | methods.scala:954 | Coll `.indices`: P(20,2,16; receiver length) | — | Runtime charge :969. |
| M045 | 2 | methods.scala:982 | Coll `.flatMap`: P(60,10,8; **result length**) | — | Runtime returns `res.length` at :1008; closure charges additional. |
| M046 | 2 | methods.scala:1013 | Coll `.patch`: P(30,2,10; receiver length + patch length) | — | Charge :1028. |
| M047 | 2 | methods.scala:1033 | Coll `.updated`: P(20,1,10; receiver length) | — | Charge :1048. |
| M048 | 2 | methods.scala:1053 | Coll `.updateMany`: P(20,2,10; receiver length) | — | Not number of updates; :1065. |
| M049 | 2 | methods.scala:1070 | Coll `.indexOf`: P(20,10,2; actual iterations) | — | Plus `DataValueComparer` per examined element; starts at `max(from,0)`. |
| M050 | 2 | methods.scala:1105 | Coll `.zip`: P(10,1,10; **left/receiver length**) | — | Not shorter/result length; :1117. |
| M051 | 2 | methods.scala:1126 | Coll `.reverse`: P(20,2,100; receiver length) | T3 | Reuses Append descriptor. |
| M052 | 2 | methods.scala:1145 | Coll `.startsWith`: P(10,1,10; receiver length) | T3 | Reuses Zip descriptor; not prefix length. |
| M053 | 2 | methods.scala:1165 | Coll `.endsWith`: P(10,1,10; receiver length) | T3 | Not suffix length. |
| M054 | 2 | methods.scala:1183 | Coll `.get`: F(30) | T3 | Optional indexed access. |
| M055 | 2 | methods.scala:1240 | Tuple inherited `.size`: F(14); `.apply`: F(30) | — | Only Coll method IDs 1 and 10 are copied. |
| M056 | 2 | methods.scala:1253 | Tuple `._1` through `._255`: F(10) each | Component must exist | Generated per tuple arity; bound from `C/sigma/data/SigmaConstants.scala:57`. |
| M057 | 2 | methods.scala:1297 | Box `.value`: F(8) | — | — |
| M058 | 2 | methods.scala:1302 | Box `.propositionBytes`: F(10) | — | — |
| M059 | 2 | methods.scala:1308 | Box `.bytes`: F(12) | — | — |
| M060 | 2 | methods.scala:1312 | Box `.bytesWithoutRef`: F(12) | — | — |
| M061 | 2 | methods.scala:1317 | Box `.id`: F(12) | — | — |
| M062 | 2 | methods.scala:1321 | Box `.creationInfo`: F(16) | — | — |
| M063 | 2 | methods.scala:1329 | Box `.getRegV5`: F(50), method ID 7 | — | Exact descriptor name in this checkout. |
| M064 | 2 | methods.scala:1338 | Box `.getReg`: F(50), method ID 19 | T3 | Explicit type argument and direct method-call support. |
| M065 | 2 | methods.scala:1349 | Box `.tokens`: F(15) | — | — |
| M066 | 2 | methods.scala:1273 | Box `.R0`, `.R1`, `.R2`, `.R3`: F(50) each | — | Generated mandatory-register methods, IDs 9–12. |
| M067 | 2 | methods.scala:1281 | Box `.R4`, `.R5`, `.R6`, `.R7`, `.R8`, `.R9`: F(50) each | — | Generated optional-register methods, IDs 13–18. |
| M068 | 2 | methods.scala:1391 | AvlTree `.digest`: F(15) | — | — |
| M069 | 2 | methods.scala:1404 | AvlTree `.enabledOperations`: F(15) | — | — |
| M070 | 2 | methods.scala:1414 | AvlTree `.keyLength`: F(15) | — | — |
| M071 | 2 | methods.scala:1422 | AvlTree `.valueLengthOpt`: F(15) | — | — |
| M072 | 2 | methods.scala:1430 | AvlTree `.isInsertAllowed`: F(15) | — | Also charged internally by insert. |
| M073 | 2 | methods.scala:1443 | AvlTree `.isUpdateAllowed`: F(15) | — | Also charged internally by update. |
| M074 | 2 | methods.scala:1456 | AvlTree `.isRemoveAllowed`: F(15) | — | Also charged internally by remove. |
| M075 | 2 | methods.scala:1469 | AvlTree `.updateOperations`: F(45) | — | — |
| M076 | 2 | methods.scala:1477 | AvlTree `.contains`: DynamicCost | — | Verifier creation + lookup. |
| M077 | 2 | methods.scala:1527 | AvlTree `.get`: DynamicCost | — | Verifier creation + lookup. |
| M078 | 2 | methods.scala:1553 | AvlTree `.getMany`: DynamicCost | — | One verifier + lookup per key. |
| M079 | 2 | methods.scala:1577 | AvlTree `.insert`: DynamicCost | T3 changes failed-insert behavior | See evaluator rows. |
| M080 | 2 | methods.scala:1603 | AvlTree `.update`: DynamicCost | — | See evaluator rows. |
| M081 | 2 | methods.scala:1630 | AvlTree `.remove`: DynamicCost | — | See evaluator rows. |
| M082 | 2 | methods.scala:1657 | AvlTree `.updateDigest`: F(40) | — | Also internal successful-operation charge. |
| M083 | 2 | methods.scala:1671 | AvlTree `.insertOrUpdate`: DynamicCost | T3 | Uses update-operation pricing. |
| M084 | 2 | methods.scala:1739 | Context `.dataInputs`: F(15) | — | — |
| M085 | 2 | methods.scala:1740 | Context `.headers`: F(15) | — | — |
| M086 | 2 | methods.scala:1741 | Context `.preHeader`: F(15) | — | — |
| M087 | 2 | methods.scala:1742 | Context `.INPUTS`: F(10) | — | Property lowering to Inputs. |
| M088 | 2 | methods.scala:1743 | Context `.OUTPUTS`: F(10) | — | Property lowering to Outputs. |
| M089 | 2 | methods.scala:1744 | Context `.HEIGHT`: F(26) | — | Property lowering to Height. |
| M090 | 2 | methods.scala:1745 | Context `.SELF`: F(10) | — | Property lowering to Self. |
| M091 | 2 | methods.scala:1746 | Context `.selfBoxIndex`: F(20) | J changes returned value | — |
| M092 | 2 | methods.scala:1747 | Context `.LastBlockUtxoRootHash`: F(15) | — | — |
| M093 | 2 | methods.scala:1748 | Context `.minerPubKey`: F(20) | — | — |
| M094 | 2 | methods.scala:1750 | Context `.getVar`: F(10) | — | Lowering to GetVar. |
| M095 | 2 | methods.scala:1755 | Context `.getVarFromInput`: F(10) | T3 | Explicit type argument. |
| M096 | 2 | methods.scala:1797 | Header `.id`: F(10) | — | — |
| M097 | 2 | methods.scala:1798 | Header `.version`: F(10) | — | — |
| M098 | 2 | methods.scala:1799 | Header `.parentId`: F(10) | — | — |
| M099 | 2 | methods.scala:1800 | Header `.ADProofsRoot`: F(10) | — | — |
| M100 | 2 | methods.scala:1801 | Header `.stateRoot`: F(10) | — | — |
| M101 | 2 | methods.scala:1802 | Header `.transactionsRoot`: F(10) | — | — |
| M102 | 2 | methods.scala:1803 | Header `.timestamp`: F(10) | — | — |
| M103 | 2 | methods.scala:1804 | Header `.nBits`: F(10) | — | — |
| M104 | 2 | methods.scala:1805 | Header `.height`: F(10) | — | — |
| M105 | 2 | methods.scala:1806 | Header `.extensionRoot`: F(10) | — | — |
| M106 | 2 | methods.scala:1807 | Header `.minerPk`: F(10) | — | — |
| M107 | 2 | methods.scala:1808 | Header `.powOnetimePk`: F(10) | — | — |
| M108 | 2 | methods.scala:1809 | Header `.powNonce`: F(10) | — | — |
| M109 | 2 | methods.scala:1810 | Header `.powDistance`: F(10) | — | — |
| M110 | 2 | methods.scala:1811 | Header `.votes`: F(10) | — | — |
| M111 | 2 | methods.scala:1815 | Header `.checkPow`: F(700) | T3 | Header version 1 throws after method charge. |
| M112 | 2 | methods.scala:1841 | PreHeader `.version`: F(10) | — | — |
| M113 | 2 | methods.scala:1842 | PreHeader `.parentId`: F(10) | — | — |
| M114 | 2 | methods.scala:1843 | PreHeader `.timestamp`: F(10) | — | — |
| M115 | 2 | methods.scala:1844 | PreHeader `.nBits`: F(10) | — | — |
| M116 | 2 | methods.scala:1845 | PreHeader `.height`: F(10) | — | — |
| M117 | 2 | methods.scala:1846 | PreHeader `.minerPk`: F(10) | — | — |
| M118 | 2 | methods.scala:1847 | PreHeader `.votes`: F(10) | — | — |
| M119 | 2 | methods.scala:1871 | Global `.groupGenerator`: F(10) | — | — |
| M120 | 2 | methods.scala:1876 | Global `.xor`: P(10,2,128; shorter byte length) | — | Calls `Xor.xorWithCosting`. |
| M121 | 2 | methods.scala:1884 | Global `.powHit`: `PowHitCostKind` | T3 | `500 + (k+1)*((msgLen+nonceLen+hLen)/128+1)*7`. |
| M122 | 2 | methods.scala:1906 | Global `.deserializeTo`: P(100,32,32; input byte length) | T3 | Charge before `DataSerializer.deserialize`. |
| M123 | 2 | methods.scala:1925 | Global `.fromBigEndianBytes`: F(10) | T3 | — |
| M124 | 2 | methods.scala:1938 | Global `.encodeNbits`: F(25) | T3 | Exact method-name casing. |
| M125 | 2 | methods.scala:1943 | Global `.decodeNbits`: F(50) | T3 | — |
| M126 | 2 | methods.scala:1957 | Global `.serialize`: DynamicCost | T3 | Writer startup + individual writer callbacks. |
| M127 | 2 | methods.scala:1986 | Global `.some`: F(5) | T3 | — |
| M128 | 2 | methods.scala:1994 | Global `.none`: F(5) | T3 | — |
| M129 | 2 | methods.scala:63,506,628,717,723 | Boolean, String, Any, Unit companions: no methods/cost descriptors | — | Included to close the companion inventory; Boolean’s `ToByte` string is not an SMethod. |

## 3. Evaluator charges and dynamic cost composition

For this section, `Evaluator.scala` abbreviates `I/sigmastate/interpreter/CErgoTreeEvaluator.scala`; `Comparer.scala` abbreviates `D/sigma/data/DataValueComparer.scala`; `Writer.scala` abbreviates `D/sigma/serialization/SigmaByteWriter.scala`.

| id | category | Scala file:line | what is charged / checked (formula or constant) | version/activation gating | notes |
|---|---|---|---|---|---|
| E001 | 3 | D/sigma/ast/values.scala:352,410,960 | Constant 5; placeholder 1; ValUse 5 at actual evaluation | — | These do have node descriptors; listed again to identify executable sites. |
| E002 | 3 | D/sigma/ast/values.scala:999,1064 | `AddToEnvironment`: F(5) for each evaluated `ValDef` | — | In addition to BlockValue overhead and RHS cost. |
| E003 | 3 | D/sigma/ast/values.scala:1047 | `AddToEnvironment`: F(5) for each closure invocation | — | Applies to callbacks invoked by collection/option operations too. |
| E004 | 3 | D/sigma/ast/values.scala:1235 | Function application: F(30), then function and argument evaluation | — | `Apply`/`FuncApplyCode`; invoked closure additionally charges E003. |
| E005 | 3 | D/sigma/ast/values.scala:1333 | Evaluate receiver → F(4) dispatch → arguments → method charge | — | Fixed methods charge at :1348; other kinds call reflected `_eval` at :1362. |
| E006 | 3 | D/sigma/ast/trees.scala:404,436; D/sigma/ast/CostKind.scala:60 | Numeric cast target: BigInt/UnsignedBigInt 30; all others 10 | T3 affects accepted conversions | Both AST casts use this helper. |
| E007 | 3 | D/sigma/ast/methods.scala:270 | Numeric-method custom cost chooses Upcast/Downcast then target cost | — | `TracedCost(TypeBasedCostItem)`; not an extra charge on top of a lowered cast. |
| E008 | 3 | D/sigma/ast/trees.scala:733 | Arithmetic dispatch uses `impl.argTpe` to charge A078–A084 | — | Charge precedes arithmetic execution. |
| E009 | 3 | D/sigma/ast/methods.scala:840,865 | Direct Coll.getOrElse F(30); Coll.map P(20,1,10; input length) | — | Separate from method-call overhead. |
| E010 | 3 | D/sigma/ast/methods.scala:1004,1084 | flatMap counts output elements; indexOf counts examined elements | — | Deferred sequence charges; nested callback/comparison charges occur first. |
| E011 | 3 | I/sigmastate/interpreter/Interpreter.scala:208,218 | `hasDeserialize` selects direct constant-pool evaluation versus substituted proposition evaluation | — | Inline path uses replaced constants and EmptyConstants; can change 1-unit placeholders into 5-unit constants. |
| E012 | 3 | Evaluator.scala:296,307,333,360,370 | Fixed/type-based/known-length charges added before operation body | — | All ultimately call `coster.add`. |
| E013 | 3 | Evaluator.scala:399 | Unknown-length `addSeqCost`: run body, obtain `nItems`, then add P cost | — | A throwing body may prevent this outer deferred charge; nested charges still occur. |
| E014 | 3 | Comparer.scala:22,255,319,354,398 | MatchType F(1) | — | Per visited SigmaBoolean node; also Coll/SigmaProp/String dispatch. No blanket multiplication by match-case position. |
| E015 | 3 | Comparer.scala:27,314 | Primitive equality F(3) | — | Number/Boolean case. |
| E016 | 3 | Comparer.scala:34,185 | Generic collection equality P(10,2,1; examined elements) | — | Plus recursively charged element equality. |
| E017 | 3 | Comparer.scala:39,332 | Tuple2 equality F(4) | — | Plus recursively compared components; short-circuit. |
| E018 | 3 | Comparer.scala:44,287,296 | GroupElement/EcPoint equality F(172) | — | DLog one point; DHT up to four comparisons. |
| E019 | 3 | Comparer.scala:48,344,349 | BigInt and UnsignedBigInt equality F(5) | Unsigned values T3 | Same descriptor. |
| E020 | 3 | Comparer.scala:52,364 | AvlTree equality F(`3+6/2`) = F(6) | — | Runtime equality inside fixed block. |
| E021 | 3 | Comparer.scala:56,394 | Box equality F(6) | — | — |
| E022 | 3 | Comparer.scala:61,369 | Option equality F(`1+8/2-1`) = F(4) | — | Plus contained equality when both Some. |
| E023 | 3 | Comparer.scala:65,386 | PreHeader equality F(4) | — | — |
| E024 | 3 | Comparer.scala:69,390 | Header equality F(6) | — | — |
| E025 | 3 | Comparer.scala:74,80 | Boolean-array and Byte-array equality: each P(15,2,128; examined elements) | — | Specialized loop exits at first difference. |
| E026 | 3 | Comparer.scala:86 | Short-array equality P(15,2,96; examined elements) | — | String equality also uses this descriptor, with full string length at :404. |
| E027 | 3 | Comparer.scala:92 | Int-array equality P(15,2,64; examined elements) | — | — |
| E028 | 3 | Comparer.scala:98 | Long-array equality P(15,2,48; examined elements) | — | — |
| E029 | 3 | Comparer.scala:104,110 | GroupElement-array P(15,5,1;n); BigInt-array P(15,7,5;n) | — | Descriptor-dispatched array equality; `n` actually examined. |
| E030 | 3 | Comparer.scala:116,122 | AvlTree-array P(15,5,2;n); Box-array P(15,5,1;n) | — | Same counting mechanism. |
| E031 | 3 | Comparer.scala:128,134 | PreHeader-array P(15,3,1;n); Header-array P(15,5,1;n) | — | Same counting mechanism. |
| E032 | 3 | Comparer.scala:323,409 | Collection length/type mismatch returns after dispatch charge; Unit equality adds no charge | — | Do not invent a collection scan or Unit fixed cost. |
| E033 | 3 | D/sigma/ast/methods.scala:1498; Evaluator.scala:73 | Create AVL verifier: P(110,20,64; proof bytes) | — | Once per AVL method invocation that reaches verifier creation. |
| E034 | 3 | D/sigma/ast/methods.scala:1502; Evaluator.scala:83,100,120 | Lookup: P(40,10,1; initial tree height) | — | contains/get once; getMany once per key. |
| E035 | 3 | D/sigma/ast/methods.scala:1506; Evaluator.scala:133,143,159 | Insert: F(15) permission + verifier + P(40,10,1; `max(h,1)`) per attempted entry + F(40) if digest exists | T3 changes failure behavior | Height captured once; entry loop short-circuits. |
| E036 | 3 | D/sigma/ast/methods.scala:1510; Evaluator.scala:169,181,189 | Update: F(15) permission + verifier + P(120,20,1; `max(h,1)`) per attempted entry + conditional F(40) | — | Height not recomputed after each operation. |
| E037 | 3 | Evaluator.scala:199,200,215,223 | InsertOrUpdate: F(15)+F(15) permissions + verifier + update P cost per attempted entry + conditional F(40) | T3 | Requires both permissions. |
| E038 | 3 | D/sigma/ast/methods.scala:1514; Evaluator.scala:233,241,246,249 | Remove: F(15) permission + verifier + P(100,15,1; `max(h,1)`) per key + F(15) digest + conditional F(40) | — | Iterates all keys; return value of `performRemove` is ignored. |
| E039 | 3 | D/sigma/ast/CostKind.scala:79; D/sigma/ast/methods.scala:1899 | powHit cost `500+(k+1)*((msgLen+nonceLen+hLen)/128+1)*7` | T3 | Intermediate arithmetic is ordinary Int, not JitCost exact arithmetic; `N` is absent from formula. |
| E040 | 3 | D/sigma/ast/methods.scala:1952 | deserializeTo: P(100,32,32; bytes.length) | T3 | Charged before deserializing data; distinct from script substitution. |
| E041 | 3 | D/sigma/ast/methods.scala:1971; Writer.scala:235 | serialize startup F(10) | T3 | Installs fixed/per-item callbacks at methods.scala:1973–1980. |
| E042 | 3 | Writer.scala:45,50,61,66,171,241 | Byte/Boolean writes and option tag: F(1) each explicit callback | T3 serialize path | Nested serialized option content charged separately. |
| E043 | 3 | Writer.scala:72,77,94,99,115,120,256 | Signed Short/Int/Long writes: F(3) each | T3 serialize path | Both ordinary and metadata overloads. |
| E044 | 3 | Writer.scala:83,88,109,126,131,248 | Unsigned Short, metadata UInt, ULong writes: F(3) each | T3 serialize path | Plain `putUInt` at :105 has **no added callback**; delegates to underlying writer. |
| E045 | 3 | Writer.scala:38,137,142,147,155,262 | Chunk/byte-array writes: P(3,1,1;n) | T3 serialize path | `n`: bytes written; `putShortBytes` uses 2. |
| E046 | 3 | Writer.scala:160,165,176 | Bit arrays P(3,1,1; **bit count**); short strings P(3,1,1; character count) | T3 serialize path | Count is not necessarily encoded-byte length. |
| E047 | 3 | Writer.scala:181,188,197,204,214 | Type/value/sequence serialization delegates to constituent writes | T3 serialize path | No extra standalone type/value fee; overload choice affects callback accounting. |

## 4. Interpreter, crypto estimation, conversions and limits

| id | category | Scala file:line | what is charged / checked (formula or constant) | version/activation gating | notes |
|---|---|---|---|---|---|
| I001 | 4 | I/sigmastate/interpreter/Interpreter.scala:514 | `interpreterInitCost = 10000 BC` | — | Library constant; node uses its wallet counterpart once per transaction, not once per input. |
| I002 | 4 | I/sigmastate/interpreter/CErgoTreeEvaluator.scala:560 | Initial accumulator = `fromBlockCost(context.initCost.toIntExact)`; limit likewise | — | Long→Int checked, then ×10 checked. |
| I003 | 4 | I/sigmastate/interpreter/Interpreter.scala:81,99 | `CostPerByteDeserialized=2 BC`; charge `2*scriptBytes.length` | Substitution path | Int `multiplyExact`, then checked Long addition to initCost. |
| I004 | 4 | I/sigmastate/interpreter/Interpreter.scala:88,246 | `CostPerTreeByte=2 BC`; charge/check `2*ergoTree.bytes.length` | hasDeserialize; retained normally under A6 | Whole serialized ErgoTree size, not only expression bytes. |
| I005 | 4 | I/org/ergoplatform/ErgoLikeInterpreter.scala:17 | DeserializeRegister invokes `deserializeMeasured`; missing register can use default | — | Same per-byte charge as context deserialization. |
| I006 | 4 | I/sigmastate/interpreter/Interpreter.scala:215,533 | Root `SigmaPropConstant`: F(50) → **5 BC**, added to initCost | — | Special root fast path, not ordinary Constant F(5). |
| I007 | 4 | I/sigmastate/SigSerializer.scala:134,138 | ParseChallenge DLog F(10); DHT F(10) | Nontrivial proof proposition | Ingredients of estimate, not added again to returned verification cost. |
| I008 | 4 | I/sigmastate/interpreter/Interpreter.scala:522,526 | ComputeCommitments Schnorr F(3400); DHT F(6450) | Nontrivial proof proposition | Estimate ingredients. |
| I009 | 4 | I/sigmastate/UnprovenTree.scala:210,216 | ToBytes Schnorr F(570); DHT F(680) | Nontrivial proof proposition | Estimate ingredients. |
| I010 | 4 | I/sigmastate/interpreter/Interpreter.scala:537,543 | DLog leaf `10+3400+570=3980`; DHT leaf `10+6450+680=7140` | — | Correspond to 398/714 BC when isolated. |
| I011 | 4 | I/sigmastate/UnprovenTree.scala:220; I/sigmastate/interpreter/Interpreter.scala:570 | AND/OR proof node: F(15) + sum(child estimates) | — | Every internal conjecture node. |
| I012 | 4 | I/sigmastate/SigSerializer.scala:142,151; I/sigmastate/interpreter/Interpreter.scala:580 | Threshold: `P(10,10,1;c) + n*P(3,3,1;c) + 15 + Σchildren`; `c=n-k` | — | Thus `10+10c+n*(3+3c)+15+Σchildren` for nonnegative c. |
| I013 | 4 | I/sigmastate/interpreter/Interpreter.scala:589,369 | Trivial proposition crypto estimate 0; verify returns reduced cost directly | — | No proof-verification charge for True/False. |
| I014 | 4 | I/sigmastate/interpreter/Interpreter.scala:280 | Sum crypto estimate in JIT units → `/10` once → add to reduced BC cost | Nontrivial proposition | Crypto subtotal truncates separately from evaluator subtotal. |
| I015 | 4 | I/sigmastate/interpreter/CErgoTreeEvaluator.scala:587 | Evaluator total JIT cost → `toBlockCost` | — | Remainder discarded at evaluator boundary. |
| I016 | 4 | D/sigma/ast/JitCost.scala:9,11,15 | JitCost wraps signed Int; `+` and `*` use `addExact`/`multiplyExact` | — | ArithmeticException on overflow; no saturation or nonnegative constructor requirement. |
| I017 | 4 | D/sigma/ast/JitCost.scala:19,29,34 | Division ordinary Int division; `toBlockCost=value/10`; `fromBlockCost=10*BC` exact | — | Truncation toward zero; maximum nonnegative convertible BC is 214,748,364. |
| I018 | 4 | D/sigma/ast/CostKind.scala:26 | P chunk calculation `(n-1)/k+1`; then exact JitCost multiply/add | — | Chunk-count arithmetic itself is ordinary Int. |
| I019 | 4 | I/sigmastate/interpreter/CostAccumulator.scala:55 | Add first; throw iff `accumulatedCost > limit` | Limit defined | Equality allowed; counter already increased when exception occurs. |
| I020 | 4 | I/sigmastate/interpreter/CostAccumulator.scala:21,78 | Initial scope stores initCost; `totalCost` reads current scope | — | Constructor/read do not independently enforce the limit. |
| I021 | 4 | I/sigmastate/eval/package.scala:38 | `newCost=addExact(current,delta)`; throw iff `newCost > limit` | — | Used for init/deserialization/crypto BC accounting. |
| I022 | 4 | I/sigmastate/interpreter/Interpreter.scala:361,372 | Reduction → crypto cost check → proof verification | — | Budget can reject before expensive crypto; invalid proof still has estimated full cost on successful execution. |
| I023 | 4 | I/sigmastate/interpreter/Interpreter.scala:374; I/sigmastate/interpreter/CErgoTreeEvaluator.scala:465,490,519 | Profiling evaluator uses separate accumulator/limit; proof helper charges only when evaluator supplied | Timing enabled | Normal verify supplies `null`; profiling measurements are not added again to returned BC cost. |
| I024 | 4 | I/sigmastate/interpreter/Interpreter.scala:173,249,519 | Soft-fork fallback returns supplied baseline cost | Recognized soft-fork exception | Reduction fallback uses initCost; deserialize fallback uses context1; not accumulated partial evaluator cost. |

## 5. Transaction accounting

Here `Tx.scala` means `EC/org/ergoplatform/modifiers/mempool/ErgoTransaction.scala`.

| id | category | Scala file:line | what is charged / checked (formula or constant) | version/activation gating | notes |
|---|---|---|---|---|---|
| T001 | 5 | Tx.scala:370; EW/org/ergoplatform/wallet/interpreter/ErgoInterpreter.scala:96 | Init = `10000 + inputCount*inputCost + dataInputCount*dataInputCost + outputCount*outputCost` BC | — | Counts supplied spending/data boxes and output candidates; checked Long arithmetic. |
| T002 | 5 | Tx.scala:391 | `startCost=addExact(initialCost,accumulatedCost)` | — | `accumulatedCost` is prior **block** cost on block-validation path. |
| T003 | 5 | Tx.scala:377,394 | Check `maxCost >= startCost` | — | `maxCost=currentParameters.maxBlockCost.toLong`; equality allowed. |
| T004 | 5 | Tx.scala:191; EW/org/ergoplatform/wallet/boxes/ErgoBoxAssetExtractor.scala:55 | Token cost = `(inOccurrences+outOccurrences+inDistinctIDs+outDistinctIDs)*tokenAccessCost` BC | — | Implemented as two checked Int sums/products and checked final sum; excludes data-box tokens. |
| T005 | 5 | Tx.scala:196,200 | Add token cost with Long `addExact`; check `maxCost >= newCost` | Asset-validation stage | Checked total includes previous transactions and current init cost. |
| T006 | 5 | Tx.scala:394,424,431,435 | Order: init check → cheap/output/value checks → asset cost/check → inputs in index order | — | No separate JIT charges for every cheap validation rule. |
| T007 | 5 | Tx.scala:133 | Per-input context: `costLimit=maxCost-currentTxCost`, `initCost=0` | — | Remaining **block** budget; prevents resetting full budget for each input. |
| T008 | 5 | Tx.scala:138,153,159,160 | Verify input; `currCost=addExact(currentTxCost,scriptCost)`; require `currCost <= maxCost`; update payload by exact addition | — | Applies also to storage-rent return cost. |
| T009 | 5 | Tx.scala:140 | Verifier Failure → `(false,maxCost+1)` | Failure path | Both script validity and cumulative cost validation then fail; sentinel is not accepted cost. |
| T010 | 5 | EW/org/ergoplatform/wallet/interpreter/ErgoInterpreter.scala:72,81; EW/org/ergoplatform/wallet/protocol/Constants.scala:21 | Storage-rent path returns **50 BC** | Age ≥ StoragePeriod; empty proof; extension variable 127 present | Bypasses ordinary script/crypto evaluation; transaction still charges init/tokens and checks resulting block total. |
| T011 | 5 | EW/org/ergoplatform/wallet/interpreter/ErgoInterpreter.scala:42,82 | Storage fee = `storageFeeFactor*box.bytes.length` nanoERG; exceptions fall back to ordinary verification | Storage-rent path | Monetary rent is not JIT cost. A returned `false` does not trigger exception recovery. |
| T012 | 5 | Tx.scala:449 | `statefulValidity(...).map(_.toInt)` | Convenience API | Narrowing is ordinary `.toInt`; block path calls `validateStateful` and retains Long instead. |

## 6. Block aggregation, parameter source, voting and overflow

| id | category | Scala file:line | what is charged / checked (formula or constant) | version/activation gating | notes |
|---|---|---|---|---|---|
| B001 | 6 | EN/org/ergoplatform/nodeView/state/ErgoState.scala:140,154 | Start block accumulator at 0L; pass previous payload into next transaction | — | Transaction returns cumulative block cost; no second summation of full cumulative totals. |
| B002 | 6 | EN/org/ergoplatform/nodeView/state/ErgoState.scala:141 | Continue while transactions remain **and costResult.isValid** | — | Stops after invalid transaction. |
| B003 | 6 | EN/org/ergoplatform/nodeView/state/ErgoState.scala:135 | Height ≤ configured checkpoint height → `Valid(0L)` | Checkpoint bypass | Transaction execution/cost validation skipped there. |
| B004 | 6 | EN/org/ergoplatform/nodeView/state/UtxoState.scala:84,85 | UtxoState delegates to `ErgoState.execTransactions`; proceeds only if valid | — | No independent `< maxBlockCost` comparison or unchecked `.sum` here. |
| B005 | 6 | EN/org/ergoplatform/nodeView/state/DigestState.scala:59 | DigestState also calls `ErgoState.execTransactions` | Digest-state path | Shares the same transaction/block cost accounting. |
| B006 | 6 | EN/org/ergoplatform/nodeView/state/UtxoState.scala:139 | Append full block to state context before validating its transactions | Epoch/version changes | Updated context supplies the applicable cost parameters. |
| B007 | 6 | EC/org/ergoplatform/settings/Parameters.scala:48,53,58,63,68 | Cost parameters read from `parametersTable`; maxBlockCost key **4** | Current epoch parameters | Token/input/data-input/output keys 5/6/7/8. |
| B008 | 6 | EC/org/ergoplatform/settings/Parameters.scala:306 | Defaults: token 100; input 2000; data input 100; output 100; max block **1,000,000 BC** | Defaults only | Voting/extension state can replace these; not hardcoded validation limits. |
| B009 | 6 | EC/org/ergoplatform/settings/Parameters.scala:372; EC/org/ergoplatform/nodeView/state/ErgoStateContext.scala:175,198,222 | Parse extension parameter values as four-byte Ints; compare announced/calculated parameters | Epoch transition; initial/light context exception | At current parameter height 0, parsed parameters/settings are adopted for calculation. |
| B010 | 6 | EC/org/ergoplatform/settings/Parameters.scala:159; EC/org/ergoplatform/settings/VotingSettings.scala:11 | Parameter vote accepted iff `count > votingLength/2` | Voting epoch processing | Strict majority, not `>=`. Positive/negative parameter ID raises/lowers value. |
| B011 | 6 | EC/org/ergoplatform/settings/Parameters.scala:168,170,174,176 | Default step `max(1,currentValue/100)`; change only if current value `< max` / `> min` | Approved vote | MaxBlockCost has no special step; min 16,384; default max Int.MaxValue/2. Checks current value, not clamped proposed value. |
| B012 | 6 | EC/org/ergoplatform/settings/Parameters.scala:344,350,358 | Token/input/data-input/output costs use same generic voting logic | Approved vote | Default minimum 0, default maximum Int.MaxValue/2; no dedicated steps. |
| B013 | 6 | EC/org/ergoplatform/settings/ValidationRules.scala:174 | `bsBlockTransactionsCost`: accumulated block cost must not exceed maxBlockCost | Validation-rule settings | Actual operators reside in T003/T005/T008 and allow equality. |
| B014 | 6 | EC/org/ergoplatform/modifiers/mempool/ErgoTransaction.scala:370,391,153; EW/org/ergoplatform/wallet/boxes/ErgoBoxAssetExtractor.scala:62 | Transaction/block accumulation uses exact arithmetic; overflow throws | — | No wrapping or saturation of accepted cumulative block cost. Token intermediate arithmetic is checked Int. |
| B015 | 6 | EN/org/ergoplatform/nodeView/state/UtxoState.scala:139,209 | Exceptions during transaction application are captured through Try flow; failure triggers rollback and returns Failure | Full-block application | Overflow is not converted into a cheap successful block. |
| B016 | 6 | EN/org/ergoplatform/nodeView/state/UtxoState.scala:87 | Physical UTXO AVL state operations occur after transaction validation | — | No extra JIT charge for these database/state-tree operations; distinguish script AVL costs. |

## 7. Version and activation branches affecting charges or charged execution

This section includes direct price/count changes and versioned behavior that can change the subsequent charged execution path. It distinguishes protocol activation from the executed tree’s version.

| id | category | Scala file:line | what is charged / checked (formula or constant) | version/activation gating | notes |
|---|---|---|---|---|---|
| G001 | 7 | C/sigma/VersionContext.scala:20,25,29,33,48,51,56; EC/org/ergoplatform/nodeView/ErgoContext.scala:28 | Activated script version = block version − 1; J threshold 2; A6/T3 threshold 3; supported maximum 3 | Header/block version 3 activates J; version 4 corresponds to v6 | Tree version and activated version are separate inputs. |
| G002 | 7 | I/sigmastate/interpreter/Interpreter.scala:246,255 | Before A6, substitution surcharge is checked but normal substitution starts from original context; A6 starts from context1 and retains it | **A6, including old-version trees** | The dropped charge is whole-tree substitution cost; measured embedded-script byte charges still accumulate. |
| G003 | 7 | D/sigma/ast/transformers.scala:261 | ByIndex default: pre-T3 eagerly evaluate default; T3 evaluate it only when index absent | T3 | Can eliminate arbitrary default-expression charges; F(30) remains. |
| G004 | 7 | D/sigma/ast/transformers.scala:628 | OptionGetOrElse default: pre-T3 eager; T3 lazy | T3 | Can eliminate default-expression charges; F(20) remains. |
| G005 | 7 | D/sigma/ast/methods.scala:79,101,169,176,184,201,252 | Select/cache v5/v6 method sets; expose unsigned companion; associate v6 numeric copies with concrete owner | T3 | Governs availability/dispatch of M008–M021 and other T3 methods. |
| G006 | 7 | D/sigma/ast/methods.scala:560,684,1222,1373,1720,1778,1829,2002 | Add v6 BigInt/group/Coll/Box/AVL/Context/Header/Global methods | T3 | Exact method costs enumerated above; old methods retain descriptors. |
| G007 | 7 | I/sigmastate/interpreter/CErgoTreeEvaluator.scala:150; I/sigmastate/eval/Extensions.scala:99 | Failed AVL insert throws pre-T3; T3 returns failure through operation result | T3 | Changes whether later digest/result/script work can execute and be charged. |
| G008 | 7 | D/sigma/serialization/ErgoTreeSerializer.scala:330,369 | SubstConstants selects J implementation; T3 additionally preserves size field when header has size bit | J; T3; serialized tree header | Base P descriptor unchanged; returned bytes and later execution/deserialization can differ. |
| G009 | 7 | D/sigma/ast/trees.scala:39 | BoolToSigmaProp pre-J permits SigmaProp-valued input; J requires Boolean cast | J | F(15) already charged; affects success/resulting crypto proposition. |
| G010 | 7 | I/sigmastate/eval/CContext.scala:51 | selfBoxIndex returns −1 pre-J; actual index under J | J | F(20) unchanged; subsequent script branches/charges may change. |
| G011 | 7 | D/sigma/data/CSigmaDslBuilder.scala:117 | xorOf old distinct-value semantics versus J XOR semantics | J | No new independent charge here; changes Boolean result and later path. |
| G012 | 7 | C/sigma/data/CollsOverArrays.scala:50,184 | J fixes array concatenation and truncates pairColl sides to matching lengths | J | Append/Zip declared rates unchanged; result shape/exceptions and later costs can differ. |
| G013 | 7 | C/sigma/data/CollsOverArrays.scala:148,282 | T3 permits equality between PairColl and CollOverArray representations | T3 | Affects equality results and short-circuit/subsequent work; no new descriptor. |
| G014 | 7 | C/sigma/ast/SType.scala:412,435,460,487,512,524; C/sigma/data/CBigInt.scala:18 | T3 adds/fixes BigInt numeric conversion cases and enforces signed BigInt bit-length bound | T3 | Numeric-cast price remains 10/30; exceptions/results affect continuation. |
| G015 | 7 | D/sigma/serialization/ValueSerializer.scala:157 | Pre-T3 serialization strips leading Upcast; T3 preserves it | T3 | Can preserve a later 10/30-unit cast when serialized expression is executed. |
| G016 | 7 | D/sigma/serialization/MethodCallSerializer.scala:53; D/sigma/serialization/transformers/ByIndexSerializer.scala:29 | T3 handles explicit method type arguments and changed ByIndex parsing | T3 | Controls which charged AST/method representation is reconstructed. |
| G017 | 7 | C/sigma/serialization/CoreDataSerializer.scala:39,78,118,140; D/sigma/serialization/DataSerializer.scala:19,39 | UnsignedBigInt/Option/Header data serialization and deserialization branches | T3 | Relevant to Global.serialize/deserializeTo; writer callback totals depend on represented data. |
| G018 | 7 | C/sigma/serialization/TypeSerializer.scala:19,111,211,228,258; C/sigma/ast/SType.scala:117,167,194 | Versioned type checks, function-type serialization, unsigned-type registration | A6 and/or T3 as each condition specifies | Enables/rejects data/expressions consumed by charged operations; no independent type-validation tariff. |
| G019 | 7 | D/sigma/ast/methods.scala:131; C/sigma/validation/SigmaValidationSettings.scala:60 | A6 changes method lookup validation rule; replaced rules 1011/1007/1008 cease being tolerated as soft forks | A6 | Can prevent a former baseline-cost soft-fork success. |
| G020 | 7 | D/org/ergoplatform/validation/ValidationRules.scala:233; C/sigma/validation/ValidationRules.scala:229,248 | Select v6 rule sets; only recognized ValidationExceptions use soft-fork fallback | A6 | ArithmeticException/CostLimitException are not universally forgiven by this handler. |
| G021 | 7 | I/sigmastate/interpreter/Interpreter.scala:304,314,325 | If activation exceeds supported maximum and tree also exceeds maximum, return `(true,initCost)`; otherwise reject tree version above activation | Activation/tree version comparison | Unsupported future-tree bypass carries baseline cost only. |
| G022 | 7 | I/sigmastate/interpreter/Interpreter.scala:133,173,249 | Recognized unparsed tree becomes TrueSigmaProp; recognized reduction/deserialization exception returns prescribed baseline | Validation settings | Unparsed-tree constant path adds I006; fallback location matters. |
| G023 | 7 | D/sigma/data/CHeader.scala:73 | Header.checkPow rejects `header.version == 1`; otherwise Autolykos2 check | T3 method; inspected header’s own version | F(700) is charged before invoking method, including version-1 failure. |
| G024 | 7 | EC/org/ergoplatform/settings/Parameters.scala:139,151; EC/org/ergoplatform/settings/VotingSettings.scala:9 | Successful fork vote increments block version; approval `votes > votingLength*softForkEpochs*9/10`; special version-2 height branch | Fork schedule | Changes activated script version through G001; no direct automatic maxBlockCost multiplier. |
| G025 | 7 | EC/org/ergoplatform/nodeView/state/ErgoStateContext.scala:130,198,222; EC/org/ergoplatform/settings/Parameters.scala:87 | Epoch processing updates voted parameters and validates header block version | Epoch/header activation | Cost rates/limit and interpreter activation derive from this updated context. |

### Important boundary findings

- The executable `Interpreter.verify` in this checkout calls `fullReduction`, which uses the direct evaluator. Its introductory historical AOT/JIT discussion should not be treated as an additional executable AOT branch.
- **All three node cumulative-cost comparisons allow equality.** A mining candidate-selection `<` comparison is outside the requested block-validation path.
- The tables exceed the suggested row range because the source contains **110 concrete AST declarations and 129 method/family entries before runtime, interpreter, transaction, block and activation sites**.
- Repeated declarations, internal charges and estimates must not simply be summed together. For example, proof-operation constants feed the crypto estimate; ordinary verification does not charge those same operations again.

### Rows I am least sure about

- **M001–M005, M027–M031, M037–M043:** constants and lowering metadata are explicit; complete reachability of every unusual, directly serialized `MethodCall` form would require additional execution tests.
- **E042–E047:** explicit writer callback sites are enumerated; aggregate costs for complex serialization depend on the exact overloads invoked, especially uncharged plain `putUInt` and inherited unsigned-byte behavior.
- **G012–G018:** these are indirect accounting effects through changed values, serialized ASTs, exceptions or subsequent control flow; they do not introduce new standalone tariffs.
