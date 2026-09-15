# JIT-cost inventory audit

## Scope and application rules

Verified checkouts:

- Sigmastate: `23dd29f612249c169d09fae9bca76d7cc02e144c`
- Ergo: `2cdbb8cf09d7ccbc060e1022e3c15bcf6a9991b1`

Reference checkouts were read-only. The supplied draft was applied mechanically, with the controller rulings below.

**The supplied enumeration contains 363 unique rows, not 385:** A=110, M=129, E=47, I=24, T=12, B=16, G=25. The ledger contains 237 rows.

The mapping below uses shared cost descriptors and explicitly identified composition as counterparts. A method mapped to an opcode row shares that pricing obligation; this does **not** establish direct serialized-method reachability or close its tests. Generic placeholders such as `METHOD-unclaimed-inventory` do not count as specific coverage. Conflicting claims still map to the corresponding obligation; section D supplies corrections.

Results under that mapping:

| Inventory result | Count |
|---|---:|
| Enumeration rows with counterparts | 337 |
| Enumeration-only rows | 26 |
| Existing ledger rows with counterparts | 221 |
| Ledger-only rows | 16 |
| Existing ledger rows lacking a Scala file:line | 228 |
| Proposed replacement rows in E/F | 20 |

### Source-path notation

Sections C, D and G use the enumeration’s prefixes. Expand these prefixes mechanically before storing an anchor:

| Prefix | Checkout | Relative directory |
|---|---|---|
| D | Sigmastate | `data/shared/src/main/scala` |
| I | Sigmastate | `interpreter/shared/src/main/scala` |
| C | Sigmastate | `core/shared/src/main/scala` |
| EC | Ergo | `ergo-core/src/main/scala` |
| EW | Ergo | `ergo-wallet/src/main/scala` |
| EN | Ergo | `src/main/scala` |

Proposed TOML rows already use expanded checkout-relative paths. `F` and `P` denote the enumeration’s fixed and per-item JIT costs; `BC` means block-cost units.

## A. Enumeration → existing ledger mapping

Semicolons separate multiple counterparts. The table maps to the final ledger after sections B/E/F are applied. Baseline counts above describe the supplied draft before application.

### A — AST declarations

| Enumeration ID | Ledger ID |
|---|---|
| A001 | EVAL-const-inline |
| A002 | OP-0x73 |
| A003 | OP-TaggedVariable-A003 |
| A004 | OP-0x82 |
| A005 | OP-0x7F |
| A006 | OP-0x80 |
| A007 | OP-0x86 |
| A008 | OP-0x83 |
| A009 | OP-0x85 |
| A010 | OP-0xD6 |
| A011 | OP-0xD7 |
| A012 | OP-0x72 |
| A013 | OP-0xD8 |
| A014 | OP-0xD9 |
| A015 | OP-frontend-Block-A015 |
| A016 | OP-frontend-ZKProofBlock-A016 |
| A017 | OP-frontend-ValNode-A017 |
| A018 | OP-frontend-Select-A018 |
| A019 | OP-frontend-Ident-A019 |
| A020 | OP-0xDA |
| A021 | OP-frontend-ApplyTypes-A021 |
| A022 | OP-frontend-MethodCallLike-A022 |
| A023 | OP-0xDC |
| A024 | OP-0xDB |
| A025 | OP-frontend-Lambda-A025 |
| A026 | OP-0xAC |
| A027 | OP-0xA3 |
| A028 | OP-0xA4 |
| A029 | OP-0xA5 |
| A030 | OP-0xA6 |
| A031 | OP-0xA7 |
| A032 | OP-0xFE |
| A033 | OP-0xDD |
| A034 | OP-0xAD |
| A035 | OP-0xB3 |
| A036 | OP-0xB4 |
| A037 | OP-0xB5 |
| A038 | OP-0xAE |
| A039 | OP-0xAF |
| A040 | OP-0xB0 |
| A041 | OP-0xB2 |
| A042 | OP-0x8C |
| A043 | OP-0xCF |
| A044 | OP-0xD0 |
| A045 | OP-0xB1 |
| A046 | OP-0xC1 |
| A047 | OP-0xC2 |
| A048 | OP-0xC3 |
| A049 | OP-0xC4 |
| A050 | OP-0xC5 |
| A051 | OP-0xC6 |
| A052 | OP-0xC7 |
| A053 | OP-0xD4 |
| A054 | OP-0xD5 |
| A055 | OP-0xE3 |
| A056 | OP-0xE4 |
| A057 | OP-0xE5 |
| A058 | OP-0xE6 |
| A059 | OP-0xD1 |
| A060 | OP-0xCD |
| A061 | OP-0xB6 |
| A062 | OP-0xCE |
| A063 | OP-0xEA |
| A064 | OP-0xEB |
| A065 | OP-0x97 |
| A066 | OP-0xFF |
| A067 | OP-0x96 |
| A068 | OP-0x98 |
| A069 | OP-0x7E |
| A070 | OP-0x7D |
| A071 | OP-0x7A |
| A072 | OP-0x7C |
| A073 | OP-0x7B |
| A074 | OP-0xEE |
| A075 | OP-0xCB |
| A076 | OP-0xCC |
| A077 | OP-0x74 |
| A078 | OP-0x9A |
| A079 | OP-0x99 |
| A080 | OP-0x9C |
| A081 | OP-0x9D |
| A082 | OP-0x9E |
| A083 | OP-0xA1 |
| A084 | OP-0xA2 |
| A085 | OP-0xF0 |
| A086 | OP-0xF1 |
| A087 | OP-0xF2 |
| A088 | OP-0xF3 |
| A089 | OP-0xF5 |
| A090 | OP-0xF6 |
| A091 | OP-0xF7 |
| A092 | OP-0xF8 |
| A093 | OP-0xE7-0xE9 |
| A094 | OP-0xE7-0xE9 |
| A095 | OP-0xE7-0xE9 |
| A096 | OP-0x9B |
| A097 | OP-0x9F |
| A098 | OP-0xA0 |
| A099 | OP-0x8F |
| A100 | OP-0x90 |
| A101 | OP-0x91 |
| A102 | OP-0x92 |
| A103 | OP-0x93 |
| A104 | OP-0x94 |
| A105 | OP-0xEC |
| A106 | OP-0xED |
| A107 | OP-0xF4 |
| A108 | OP-0xB7 |
| A109 | OP-0x95 |
| A110 | OP-0xEF |

### M — method descriptors

| Enumeration ID | Ledger ID |
|---|---|
| M001 | EVAL-numeric-cast |
| M002 | EVAL-numeric-cast |
| M003 | EVAL-numeric-cast |
| M004 | EVAL-numeric-cast |
| M005 | EVAL-numeric-cast |
| M006 | METHOD-numeric-toBytes-toBits |
| M007 | METHOD-numeric-toBytes-toBits |
| M008 | METHOD-numeric-bitwise |
| M009 | METHOD-numeric-bitwise; METHOD-ubigint-bitwise |
| M010 | METHOD-numeric-bitwise; METHOD-ubigint-bitwise |
| M011 | METHOD-numeric-bitwise; METHOD-ubigint-bitwise |
| M012 | METHOD-numeric-shift; METHOD-ubigint-shift |
| M013 | METHOD-numeric-shift; METHOD-ubigint-shift |
| M014 | METHOD-bigint-toUnsigned |
| M015 | METHOD-bigint-toUnsignedMod |
| M016 | METHOD-ubigint-modInverse |
| M017 | METHOD-ubigint-plusMod |
| M018 | METHOD-ubigint-subtractMod |
| M019 | METHOD-ubigint-multiplyMod |
| M020 | METHOD-ubigint-mod |
| M021 | METHOD-ubigint-toSigned |
| M022 | METHOD-groupelement-getEncoded |
| M023 | METHOD-groupelement-exp |
| M024 | METHOD-groupelement-expUnsigned |
| M025 | OP-0xA0 |
| M026 | METHOD-groupelement-negate |
| M027 | OP-0xD0 |
| M028 | METHOD-sigmaprop-isProven-M028 |
| M029 | OP-0xE6 |
| M030 | OP-0xE4 |
| M031 | OP-0xE5 |
| M032 | METHOD-option-map |
| M033 | METHOD-option-filter |
| M034 | OP-0xB1 |
| M035 | OP-0xB2 |
| M036 | OP-0xAD |
| M037 | OP-0xAE |
| M038 | OP-0xB0 |
| M039 | OP-0xAF |
| M040 | OP-0xB4 |
| M041 | OP-0xB5 |
| M042 | OP-0xB3 |
| M043 | OP-0xB2 |
| M044 | METHOD-coll-indices |
| M045 | METHOD-coll-flatMap |
| M046 | METHOD-coll-patch |
| M047 | METHOD-coll-updated |
| M048 | METHOD-coll-updateMany |
| M049 | METHOD-coll-indexOf |
| M050 | METHOD-coll-zip |
| M051 | METHOD-coll-reverse |
| M052 | METHOD-coll-startsEndsWith |
| M053 | METHOD-coll-startsEndsWith |
| M054 | METHOD-coll-get |
| M055 | OP-0xB1; OP-0xB2 |
| M056 | OP-0x8C |
| M057 | OP-0xC1 |
| M058 | OP-0xC2 |
| M059 | OP-0xC3 |
| M060 | OP-0xC4 |
| M061 | OP-0xC5 |
| M062 | OP-0xC7 |
| M063 | METHOD-box-getReg |
| M064 | METHOD-box-getReg |
| M065 | METHOD-box-tokens |
| M066 | METHOD-box-registers-R0-R3 |
| M067 | METHOD-box-registers-R4-R9 |
| M068 | METHOD-avl-props |
| M069 | METHOD-avl-props |
| M070 | METHOD-avl-props |
| M071 | METHOD-avl-props |
| M072 | METHOD-avl-props |
| M073 | METHOD-avl-props |
| M074 | METHOD-avl-props |
| M075 | METHOD-avl-updateOperations |
| M076 | METHOD-avl-contains |
| M077 | METHOD-avl-get |
| M078 | METHOD-avl-getMany |
| M079 | METHOD-avl-insert |
| M080 | METHOD-avl-update |
| M081 | METHOD-avl-remove |
| M082 | METHOD-avl-updateDigest |
| M083 | METHOD-avl-insertOrUpdate |
| M084 | METHOD-context-dataInputs |
| M085 | METHOD-context-headers |
| M086 | METHOD-context-preHeader |
| M087 | OP-0xA4 |
| M088 | OP-0xA5 |
| M089 | OP-0xA3 |
| M090 | OP-0xA7 |
| M091 | METHOD-context-selfBoxIndex |
| M092 | METHOD-context-lastBlockUtxoRootHash |
| M093 | METHOD-context-minerPubKey |
| M094 | OP-0xE3 |
| M095 | METHOD-context-getVarFromInput |
| M096 | METHOD-header-props |
| M097 | METHOD-header-props |
| M098 | METHOD-header-props |
| M099 | METHOD-header-props |
| M100 | METHOD-header-props |
| M101 | METHOD-header-props |
| M102 | METHOD-header-props |
| M103 | METHOD-header-props |
| M104 | METHOD-header-props |
| M105 | METHOD-header-props |
| M106 | METHOD-header-props |
| M107 | METHOD-header-props |
| M108 | METHOD-header-props |
| M109 | METHOD-header-props |
| M110 | METHOD-header-props |
| M111 | METHOD-header-checkPow |
| M112 | METHOD-preheader-props |
| M113 | METHOD-preheader-props |
| M114 | METHOD-preheader-props |
| M115 | METHOD-preheader-props |
| M116 | METHOD-preheader-props |
| M117 | METHOD-preheader-props |
| M118 | METHOD-preheader-props |
| M119 | METHOD-global-groupGenerator |
| M120 | METHOD-global-xor |
| M121 | METHOD-global-powHit |
| M122 | METHOD-global-deserializeTo |
| M123 | METHOD-global-fromBigEndianBytes |
| M124 | METHOD-global-encodeNbits |
| M125 | METHOD-global-decodeNbits |
| M126 | METHOD-global-serialize |
| M127 | METHOD-global-some |
| M128 | METHOD-global-none |
| M129 | METHOD-empty-companions-M129 |

M024 adds the distinct unsigned-exponent method. M066/M067 add generated register-accessor identities outside the existing `getReg` row’s explicitly stated IDs 7/19. Their prices are shared descriptors, not additional charges on top of those descriptors.

### E — evaluator charges

| Enumeration ID | Ledger ID |
|---|---|
| E001 | EVAL-const-inline; OP-0x73; OP-0x72; ORDER-constplaceholder |
| E002 | OP-0xD6; ORDER-blockvalue-valdef |
| E003 | EVAL-addtoenv |
| E004 | OP-0xDA |
| E005 | OP-0xDC; OP-0xDB |
| E006 | EVAL-numeric-cast |
| E007 | EVAL-numeric-cast |
| E008 | EVAL-arith-bigint |
| E009 | OP-0xB2; OP-0xAD |
| E010 | METHOD-coll-flatMap; METHOD-coll-indexOf |
| E011 | EVAL-hasdeserialize-fork |
| E012 | EVAL-deferred-charge-on-exception |
| E013 | EVAL-deferred-charge-on-exception |
| E014 | EVAL-eq-matchtype; EVAL-eq-sigmaboolean |
| E015 | EVAL-eq-prim |
| E016 | EVAL-eq-coll-fallback |
| E017 | EVAL-eq-tuple |
| E018 | EVAL-eq-groupelement |
| E019 | EVAL-eq-bigint |
| E020 | EVAL-eq-avltree |
| E021 | EVAL-eq-box |
| E022 | EVAL-eq-option |
| E023 | EVAL-eq-preheader |
| E024 | EVAL-eq-header |
| E025 | EVAL-eq-coll-descriptor |
| E026 | EVAL-eq-coll-descriptor |
| E027 | EVAL-eq-coll-descriptor |
| E028 | EVAL-eq-coll-descriptor |
| E029 | EVAL-eq-coll-descriptor |
| E030 | EVAL-eq-coll-descriptor; EVAL-eq-boxcollection |
| E031 | EVAL-eq-coll-descriptor |
| E032 | EVAL-eq-mismatch-and-unit-E032 |
| E033 | METHOD-avl-contains; METHOD-avl-get; METHOD-avl-getMany; METHOD-avl-insert; METHOD-avl-update; METHOD-avl-insertOrUpdate; METHOD-avl-remove |
| E034 | METHOD-avl-contains; METHOD-avl-get; METHOD-avl-getMany |
| E035 | METHOD-avl-insert |
| E036 | METHOD-avl-update |
| E037 | METHOD-avl-insertOrUpdate |
| E038 | METHOD-avl-remove |
| E039 | METHOD-global-powHit |
| E040 | METHOD-global-deserializeTo |
| E041 | METHOD-global-serialize |
| E042 | METHOD-global-serialize-E042 |
| E043 | METHOD-global-serialize-E043 |
| E044 | METHOD-global-serialize-E044 |
| E045 | METHOD-global-serialize-E045 |
| E046 | METHOD-global-serialize-E046 |
| E047 | METHOD-global-serialize-E047 |

### I — interpreter

| Enumeration ID | Ledger ID |
|---|---|
| I001 | INTERP-init-cost |
| I002 | INTERP-jitcost-bounds |
| I003 | INTERP-embedded-script-deser |
| I004 | INTERP-deser-subst |
| I005 | INTERP-embedded-script-deser |
| I006 | INTERP-eval-sigmaprop-constant |
| I007 | INTERP-crypto-dlog; INTERP-crypto-dht |
| I008 | INTERP-crypto-dlog; INTERP-crypto-dht |
| I009 | INTERP-crypto-dlog; INTERP-crypto-dht |
| I010 | INTERP-crypto-dlog; INTERP-crypto-dht |
| I011 | INTERP-crypto-conjunction |
| I012 | INTERP-crypto-threshold |
| I013 | INTERP-crypto-trivial-I013 |
| I014 | INTERP-crypto-trunc; ROUND-crypto-per-input |
| I015 | ROUND-snap-per-input |
| I016 | INTERP-jitcost-bounds |
| I017 | INTERP-toblockcost; INTERP-jitcost-bounds |
| I018 | ROUND-perItem-chunking |
| I019 | INTERP-costlimit-op |
| I020 | INTERP-accumulator-initial-scope-I020 |
| I021 | INTERP-costlimit-op |
| I022 | ORDER-crypto-before-verify |
| I023 | INTERP-profiling-cost-isolation-I023 |
| I024 | VERSION-tree-version-gate |

### T — transaction

| Enumeration ID | Ledger ID |
|---|---|
| T001 | TX-init-formula; INTERP-init-cost |
| T002 | LIMIT-tx-start; BLOCK-per-tx-cap |
| T003 | LIMIT-tx-start; BLOCK-sum-op |
| T004 | TX-token-cost |
| T005 | TX-token-cost; BLOCK-sum-op |
| T006 | ORDER-init-token |
| T007 | LIMIT-per-input |
| T008 | TX-accumulator-shared; BLOCK-sum-op |
| T009 | TX-verifier-failure-sentinel-T009 |
| T010 | TX-storage-rent |
| T011 | TX-storage-rent |
| T012 | TX-statefulValidity-narrowing-T012 |

### B — block and parameters

| Enumeration ID | Ledger ID |
|---|---|
| B001 | BLOCK-accum-equiv; BLOCK-per-tx-cap |
| B002 | BLOCK-stop-after-invalid-B002 |
| B003 | TX-scripts-skipped-pairing |
| B004 | LIMIT-block-sum |
| B005 | BLOCK-digest-state-accounting-B005 |
| B006 | BLOCK-updated-context-before-validation-B006 |
| B007 | TX-voted-params |
| B008 | BLOCK-cost-parameter-defaults-B008 |
| B009 | BLOCK-param-voting |
| B010 | BLOCK-param-voting |
| B011 | BLOCK-param-voting |
| B012 | BLOCK-param-voting |
| B013 | LIMIT-block-sum; BLOCK-sum-op |
| B014 | BLOCK-overflow |
| B015 | BLOCK-overflow-fixture; BLOCK-rejection-state-unchanged |
| B016 | BLOCK-physical-utxo-operations-B016 |

### G — version branches

| Enumeration ID | Ledger ID |
|---|---|
| G001 | VERSION-jit-activation |
| G002 | VERSION-subst-retention |
| G003 | VERSION-v6-lazy-defaults |
| G004 | VERSION-v6-lazy-defaults |
| G005 | VERSION-v6-method-gate |
| G006 | VERSION-v6-method-gate |
| G007 | VERSION-G007 |
| G008 | VERSION-G008 |
| G009 | VERSION-G009 |
| G010 | VERSION-G010; VERSION-selfboxindex-bug |
| G011 | VERSION-G011 |
| G012 | VERSION-G012 |
| G013 | VERSION-G013 |
| G014 | VERSION-G014 |
| G015 | VERSION-G015 |
| G016 | VERSION-G016 |
| G017 | VERSION-G017 |
| G018 | VERSION-G018 |
| G019 | VERSION-G019 |
| G020 | VERSION-G020 |
| G021 | VERSION-tree-version-gate |
| G022 | VERSION-tree-version-gate |
| G023 | VERSION-header-checkPow-G023 |
| G024 | BLOCK-param-voting |
| G025 | BLOCK-param-voting |

## B. Enumeration-only rows — proposed additions

Each inline table is a separate proposed ledger row. These are inventory additions, not evidence of closed conformance.

### A003

```toml
{id="OP-TaggedVariable-A003", cat="OP", scala="data/shared/src/main/scala/sigma/ast/values.scala:444", rust="unverified", layer="L1,L2", state="OPEN", tests=[], note="A003: TaggedVariable declares FixedCost(1), but TaggedVariableNode inherits the throwing Value.eval with no charge. Serializer is registered at data/shared/src/main/scala/sigma/serialization/ValueSerializer.scala:94. Verify serialized-node rejection and charged-to-failure behavior; do not treat the declaration as an executable one-unit charge."}
```

### A015

```toml
{id="OP-frontend-Block-A015", cat="OP", scala="data/shared/src/main/scala/sigma/ast/values.scala:1091", rust="unverified", layer="L1", state="N-A", tests=[], note="A015: frontend Block has unsupported costKind and no wire serializer in ValueSerializer.serializers; executable bindings use BlockValue. No separate block-validation charge."}
```

### A016

```toml
{id="OP-frontend-ZKProofBlock-A016", cat="OP", scala="data/shared/src/main/scala/sigma/ast/values.scala:1121", rust="unverified", layer="L1", state="N-A", tests=[], note="A016: frontend ZKProofBlock has unsupported costKind and no wire serializer in ValueSerializer.serializers. No executable charge on the serialized block-validation path."}
```

### A017

```toml
{id="OP-frontend-ValNode-A017", cat="OP", scala="data/shared/src/main/scala/sigma/ast/values.scala:1161", rust="unverified", layer="L1", state="N-A", tests=[], note="A017: frontend named binding has unsupported costKind and no wire serializer; executable bindings use ValDef inside BlockValue."}
```

### A018

```toml
{id="OP-frontend-Select-A018", cat="OP", scala="data/shared/src/main/scala/sigma/ast/values.scala:1186", rust="unverified", layer="L1", state="N-A", tests=[], note="A018: unresolved frontend Select has unsupported costKind and no wire serializer. This is distinct from serialized SelectField and method/property calls."}
```

### A019

```toml
{id="OP-frontend-Ident-A019", cat="OP", scala="data/shared/src/main/scala/sigma/ast/values.scala:1201", rust="unverified", layer="L1", state="N-A", tests=[], note="A019: frontend Ident has unsupported costKind and no wire serializer; resolved environment accesses use ValUse."}
```

### A021

```toml
{id="OP-frontend-ApplyTypes-A021", cat="OP", scala="data/shared/src/main/scala/sigma/ast/values.scala:1276", rust="unverified", layer="L1", state="N-A", tests=[], note="A021: frontend type application has unsupported costKind and no wire serializer. It does not introduce an executable block-validation charge."}
```

### A022

```toml
{id="OP-frontend-MethodCallLike-A022", cat="OP", scala="data/shared/src/main/scala/sigma/ast/values.scala:1295", rust="unverified", layer="L1", state="N-A", tests=[], note="A022: unresolved frontend method call has unsupported costKind and no wire serializer. Resolved MethodCall has its own four-unit dispatch charge."}
```

### A025

```toml
{id="OP-frontend-Lambda-A025", cat="OP", scala="data/shared/src/main/scala/sigma/ast/values.scala:1416", rust="unverified", layer="L1", state="N-A", tests=[], note="A025: frontend Lambda has unsupported costKind and no wire serializer; executable closures use FuncValue."}
```

### M024

```toml
{id="METHOD-groupelement-expUnsigned", cat="METHOD", scala="data/shared/src/main/scala/sigma/ast/methods.scala:656", rust="unverified", layer="L1,L2", state="OPEN", tests=[], note="M024: GroupElement.expUnsigned is method ID 6, available for tree version >=3. Reuses Exponentiate FixedCost(900), excluding receiver, argument and MethodCall charges. Signed exp is method ID 3."}
```

### M028

```toml
{id="METHOD-sigmaprop-isProven-M028", cat="METHOD", scala="data/shared/src/main/scala/sigma/ast/methods.scala:707", rust="unverified", layer="L1", state="N-A", tests=[], note="M028: frontend-only isProven descriptor has null costKind. It is not an executable zero-cost proof verifier; proof verification belongs to Interpreter. This N-A applies to an independent method tariff, not a claim that every unusual serialized MethodCall is unreachable."}
```

### M066

```toml
{id="METHOD-box-registers-R0-R3", cat="METHOD", scala="data/shared/src/main/scala/sigma/ast/methods.scala:1277", rust="unverified", layer="L1,L2", state="OPEN", tests=[], note="M066: generated mandatory-register accessors R0 through R3 each reuse ExtractRegisterAs FixedCost(50). Method IDs are idOfs + register index + 1. Separate accessor identities from explicit getReg IDs 7 and 19; direct-call reachability remains to be tested."}
```

### M067

```toml
{id="METHOD-box-registers-R4-R9", cat="METHOD", scala="data/shared/src/main/scala/sigma/ast/methods.scala:1281", rust="unverified", layer="L1,L2", state="OPEN", tests=[], note="M067: generated optional-register accessors R4 through R9, IDs 13 through 18, each reuse ExtractRegisterAs FixedCost(50). Separate accessor identities from explicit getReg IDs 7 and 19; direct-call reachability remains to be tested."}
```

### M129

```toml
{id="METHOD-empty-companions-M129", cat="METHOD", scala="data/shared/src/main/scala/sigma/ast/methods.scala:63", rust="unverified", layer="L1", state="N-A", tests=[], note="M129: Boolean, String, Any and Unit companions introduce no SMethod descriptors; their declarations are at methods.scala:506,628,717,723. An empty method inventory has no independent executable tariff."}
```

### E032

```toml
{id="EVAL-eq-mismatch-and-unit-E032", cat="EVAL", scala="data/shared/src/main/scala/sigma/data/DataValueComparer.scala:323", rust="unverified", layer="L1,L2", state="OPEN", tests=[], note="E032: collection length or element-type mismatch returns false after the collection MatchType charge, without scan cost. Unit equality at DataValueComparer.scala:409 adds no charge. Verify both zero-additional-cost branches."}
```

### I013

```toml
{id="INTERP-crypto-trivial-I013", cat="INTERP", scala="interpreter/shared/src/main/scala/sigmastate/interpreter/Interpreter.scala:589", rust="unverified", layer="L1,L2", state="OPEN", tests=[], note="I013: trivial SigmaBoolean crypto estimate is zero. verify returns true or false with reduced.cost at Interpreter.scala:369; it does not add a nontrivial proof-verification charge."}
```

### I020

```toml
{id="INTERP-accumulator-initial-scope-I020", cat="INTERP", scala="interpreter/shared/src/main/scala/sigmastate/interpreter/CostAccumulator.scala:21", rust="unverified", layer="L1,L3", state="OPEN", tests=[], note="I020: constructor stores initialCost in the initial scope; totalCost at CostAccumulator.scala:78 reads currentScope.currentCost. Neither constructor nor read independently checks the limit; add performs the comparison."}
```

### I023

```toml
{id="INTERP-profiling-cost-isolation-I023", cat="INTERP", scala="interpreter/shared/src/main/scala/sigmastate/interpreter/Interpreter.scala:374", rust="unverified", layer="L1,L2", state="OPEN", tests=[], note="I023: timing-enabled verification supplies a separate profiling evaluator; ordinary verification supplies null. Profiling accumulator creation and optional proof-helper charging are at CErgoTreeEvaluator.scala:465,490,519. These helper measurements are not added again to the returned block cost."}
```

### T009

```toml
{id="TX-verifier-failure-sentinel-T009", cat="TX", scala="ergo-core/src/main/scala/org/ergoplatform/modifiers/mempool/ErgoTransaction.scala:140", rust="unverified", layer="L3,L5", state="OPEN", tests=[], note="T009: verifier Failure yields false and maxCost+1 as a rejection sentinel. Subsequent script and accumulated-cost checks reject; this sentinel is not an accepted execution cost."}
```

### T012

```toml
{id="TX-statefulValidity-narrowing-T012", cat="TX", scala="ergo-core/src/main/scala/org/ergoplatform/modifiers/mempool/ErgoTransaction.scala:449", rust="unverified", layer="L1", state="N-A", tests=[], note="T012: convenience statefulValidity converts successful Long cost with ordinary toInt. Block validation calls validateStateful directly and retains Long, so this narrowing is outside the requested block-validation accounting path."}
```

### B002

```toml
{id="BLOCK-stop-after-invalid-B002", cat="BLOCK", scala="src/main/scala/org/ergoplatform/nodeView/state/ErgoState.scala:141", rust="unverified", layer="L3,L5", state="OPEN", tests=[], note="B002: transaction loop continues only while transactions remain and costResult.isValid. Later transactions are not validated or charged after the first invalid result."}
```

### B005

```toml
{id="BLOCK-digest-state-accounting-B005", cat="BLOCK", scala="src/main/scala/org/ergoplatform/nodeView/state/DigestState.scala:59", rust="unverified", layer="L1,L5", state="OPEN", tests=[], note="B005: DigestState delegates to ErgoState.execTransactions and converts the validation result to Try. It shares cumulative transaction/block accounting with the UTXO-state path."}
```

### B006

```toml
{id="BLOCK-updated-context-before-validation-B006", cat="BLOCK", scala="src/main/scala/org/ergoplatform/nodeView/state/UtxoState.scala:139", rust="unverified", layer="L4,L5", state="OPEN", tests=[], note="B006: appendFullBlock produces newStateContext before applyTransactions. Transaction validation receives that updated context, including applicable epoch parameters and block version."}
```

### B008

```toml
{id="BLOCK-cost-parameter-defaults-B008", cat="BLOCK", scala="ergo-core/src/main/scala/org/ergoplatform/settings/Parameters.scala:306", rust="unverified", layer="L1,L4", state="OPEN", tests=[], note="B008: default BC values are tokenAccessCost=100, inputCost=2000, dataInputCost=100, outputCost=100 and maxBlockCost=1000000; see Parameters.scala:306,308,310,312,318. Current voted parameters replace defaults during validation."}
```

### B016

```toml
{id="BLOCK-physical-utxo-operations-B016", cat="BLOCK", scala="src/main/scala/org/ergoplatform/nodeView/state/UtxoState.scala:87", rust="unverified", layer="L1", state="N-A", tests=[], note="B016: physical stateChanges and AVL database operations execute after transaction validation and have no independent JIT tariff. Script-level AVL method charges are separate obligations."}
```

### G023

```toml
{id="VERSION-header-checkPow-G023", cat="VERSION", scala="data/shared/src/main/scala/sigma/data/CHeader.scala:73", rust="unverified", layer="L1,L2", state="OPEN", tests=[], note="G023: tree-version-3 checkPow method charges FixedCost(700) before invocation; inspected header.version==1 then throws. Other header versions use Autolykos2 verification. Method descriptor is methods.scala:1815 and fixed-method charge order is values.scala:1348."}
```

## C. Ledger-only rows

These 16 rows have no specific enumeration counterpart under section A. An absence-verification anchor identifies the relevant registry or dispatch, not a nonexistent charge.

| Ledger ID | Verified Scala anchor or result | Finding |
|---|---|---|
| OP-0x81 | `D/sigma/serialization/ValueSerializer.scala:42` | Complete serializer registry has no bare UnitConstant registration. This supports the wire-opcode exclusion, not a claim that Unit data cannot occur as a constant. |
| OP-0x87-0x8B | `D/sigma/serialization/ValueSerializer.scala:47` | Registry registers SelectField; no separate Select1–Select5 serializers. |
| OP-0xDF | `D/sigma/serialization/ValueSerializer.scala:42` | Complete registry has no bare NoneValue serializer. Option data serialization is a separate path. |
| EVAL-eq-coll-sigmaprop-descriptor | **NOT FOUND IN SCALA** | No specialized Coll[SigmaProp] descriptor. `D/sigma/data/DataValueComparer.scala:229` falls back to `equalColls` at line 235 when no descriptor exists. |
| EVAL-eq-tokens | `D/sigma/data/DataValueComparer.scala:183` | Token equality is composition of generic collection, tuple, byte-collection and primitive equality. No dedicated token tariff. See corrected formula in D. |
| EVAL-max-depth | **NOT FOUND IN SCALA** | No corresponding fixed depth-100 evaluator guard in the supplied Scala implementation. `D/sigma/ast/values.scala:113` delegates to node evaluation without that guard. |
| EVAL-avl-cost-height | `I/sigmastate/eval/CAvlTreeVerifier.scala:24` | Scala exposes `rootNodeHeight` as `treeHeight`. The wrapper exists; the ledger’s complete malformed-metadata/digest-byte formula is not established by this wrapper. `BatchAVLVerifier` is an imported dependency whose implementation is absent from the supplied checkouts. |
| METHOD-unclaimed-inventory | `D/sigma/ast/methods.scala:63` | Inventory obligation, not a tariff. Method collection/caching occurs at lines 63–110, with concrete companions later in the file. Do not use this catch-all to conceal specific missing methods. |
| ORDER-pre-v3-upcast | `D/sigma/ast/SigmaBuilder.scala:750` | Deserialization builder suppresses automatic operand upcasts for tree version ≥3; older trees call the inherited insertion logic. Evaluation cost occurs in the inserted cast node. |
| ORDER-hof-charge | `D/sigma/ast/transformers.scala:40` | Obligation exists, but the stated order is wrong: Map evaluates input, then mapper, then charges collection overhead, then invokes callbacks. |
| ORDER-comparison-charge | `D/sigma/ast/trees.scala:1092` | LT evaluates both operands before its type-based charge. LE/GT/GE follow the same structure. |
| ORDER-bitop-charge-then-reject | **NOT FOUND IN SCALA** | Claimed charge-then-reject behavior does not exist. BitOp has no evaluator override at `D/sigma/ast/trees.scala:911`; inherited `Value.eval` throws without charging at `D/sigma/ast/values.scala:101`. |
| BLOCK-parallel-equiv | **NOT FOUND IN SCALA** | No corresponding parallel Scala validator obligation. Sequential reference is `EN/org/ergoplatform/nodeView/state/ErgoState.scala:140`. This is a Rust implementation-equivalence obligation. |
| VERSION-pre-v3-upcast | `D/sigma/ast/SigmaBuilder.scala:750` | Genuine version branch omitted from the enumeration. G015 concerns serialization stripping and is a different branch. |
| VERSION-v3-bool-root | **NOT FOUND IN SCALA** | Claimed ordinary v3 Boolean-root acceptance/coercion is unsupported. Root validation requires SigmaProp at `D/org/ergoplatform/validation/ValidationRules.scala:45`; ordinary `evalToCrypto` rejects Boolean results at `I/sigmastate/interpreter/CErgoTreeEvaluator.scala:535`. |
| VERSION-hardening-creation-height | `EC/org/ergoplatform/modifiers/mempool/ErgoTransaction.scala:384` | Genuine non-cost branch: blockVersion ≤ HardeningVersion uses zero; otherwise maximum input creation height. Existing N-A rationale is appropriate for a separate tariff. |

For `VERSION-v3-bool-root`, a different conversion exists at `I/sigmastate/interpreter/Interpreter.scala:599`. It is called by deserialize substitution at line 155 and has no v3 condition there. Do not use that helper as evidence for the ledger’s ordinary-root claim.

## D. Constant/formula mismatches and source-verified corrections

### Definite corrections

| Affected rows | Source-verified truth |
|---|---|
| OP-0x73; ORDER-constplaceholder; E001 | Constant-pool lookup happens **before** the one-unit charge: `D/sigma/ast/values.scala:409`, then line 410. An out-of-bounds lookup does not reach this node’s charge. The ledger’s “charged before bounds check” claim is reversed. |
| OP-0xD6; A010/E002 | Standalone `ValDef.costKind` throws at `D/sigma/ast/values.scala:935`. The five-unit binding charge belongs to BlockValue’s environment update at line 999, after RHS evaluation/type checking. Preserve both facts instead of labeling the descriptor F(5). |
| OP-0xE7-0xE9; A093–A095 | ModQ declares F(1) at `D/sigma/ast/trees.scala:962`; modular binary operations inherit F(1) at line 973. Their `costKind` does **not** throw. They lack evaluator implementations and inherit the uncharged throwing evaluator at `D/sigma/ast/values.scala:101`. |
| OP-0xF2, OP-0xF3, OP-0xF5, OP-0xF6, OP-0xF7, OP-0xF8; ORDER-bitop-charge-then-reject; A087–A092 | Declared F(1) does **not** imply an accumulated charge. BitOp lacks `eval` at `D/sigma/ast/trees.scala:911`; `NotReadyValue` adds no evaluator at `D/sigma/ast/values.scala:424`; inherited `eval` throws at line 101. Remove the charge-then-reject assertion. |
| OP-0x8F–OP-0x92; A099–A102 | Descriptor kind is **TypeBasedCost**, with 20 in every branch, not FixedCost. Anchors: `D/sigma/ast/trees.scala:1106`, `:1133`, `:1160`, `:1187`. Successful amounts agree. |
| OP-0x7D, OP-0x7E; A069/A070/E006 | Cast pricing depends on the **target** type: BigInt/UnsignedBigInt 30; every other target 10. `D/sigma/ast/CostKind.scala:60`. “BigInt-family” must not imply that a BigInt source alone costs 30. |
| OP-0x9F; M023/M024 | The note identifying signed `GroupElement.exp` as `(7,6)` is wrong. Signed exp has method ID **3** at `D/sigma/ast/methods.scala:647`; ID **6** is expUnsigned at line 656. Both reuse F(900). |
| METHOD-numeric-toBytes-toBits; M006/M007 | These methods are already in `v5Methods`, not introduced only in v6. See `D/sigma/ast/methods.scala:461`, particularly lines 467–468. Both cost 5; unsigned receiver availability remains versioned. |
| VERSION-v6-method-gate; G005/G006 | v5/v6 method-set selection uses **tree version ≥3**, not merely activatedScriptVersion ≥3: `D/sigma/ast/methods.scala:79`, `:101`, `:252`, and companion-specific gates. Activated version separately changes validation-rule selection at line 131. |
| VERSION-subst-retention; G002 | What is retained is the **whole-tree substitution cost**, not substituted constants. Both branches check `2*ergoTree.bytes.length` BC; A6 uses `context1`, older activation uses original context. `I/sigmastate/interpreter/Interpreter.scala:246`, `:255`. This activation gate also affects old-version trees. |
| INTERP-deser-subst; I004/G002 | The whole-tree surcharge is checked before substitution, but normal pre-A6 execution drops it from the context used for substitution. Thus “added to initCost” needs the retention branch above. Recognized substitution fallback uses context1. |
| INTERP-costlimit-op; I019/I021 | The ledger note saying “Scala compares block units” is too broad. `CostAccumulator` compares **JIT units** at `I/sigmastate/interpreter/CostAccumulator.scala:55`; `addCostChecked` compares **BC Longs** at `I/sigmastate/eval/package.scala:38`. Both reject only `>` and allow equality. |
| ORDER-hof-charge | Map evaluates the mapper **before** its known-length overhead charge: `D/sigma/ast/transformers.scala:40`. Exists similarly evaluates its condition before overhead at line 160. The ledger’s overhead-before-lambda order is wrong. Closure invocation separately charges environment insertion. |
| VERSION-v3-bool-root | No such ordinary v3-root branch was found. SigmaProp root validation and ordinary evaluator result checking contradict the claim; see C. Deserialize substitution’s Boolean conversion is a different path. |
| EVAL-eq-tokens | There is no universal MatchType charge before primitive equality. For equal, well-typed token collections containing `q` `(32-byte ID, Long amount)` tuples, the composition is `1 + P(10,2,1;q) + q*(4 + 1 + P(15,2,128;32) + 3) = 11 + 27*q`. The ledger’s **two** per-token MatchType charges overcounts by one per token. Anchors: `D/sigma/data/DataValueComparer.scala:183`, `:319`, `:332`, `:314`. Early mismatch changes examined counts and can skip amount comparison. |

### Required formula clarifications

These are omissions or overly broad descriptions rather than different stated numeric constants.

| Affected rows | Source-verified truth |
|---|---|
| OP-0x96 / OP-0x97; A065/A067 | AND/OR count **examined Boolean elements**, including the terminating element, and charge after their short-circuit loop. They do not always price full input length. `D/sigma/ast/trees.scala:222`, `:292` and preceding evaluator bodies. |
| OP-0x74; A077 | SubstConstants uses the returned **original constant count**, not replacement count. `D/sigma/ast/trees.scala:655` and its preceding evaluation body. |
| OP-0xB4; A036 | Slice prices `max(0, until-from)`, using ordinary Int subtraction, rather than actual sliced-result length. `D/sigma/ast/transformers.scala:106` and preceding evaluator body. |
| OP-0xD0; A044/M027 | P(35,6,1) counts SigmaBoolean proposition nodes, not serialized bytes. `D/sigma/ast/transformers.scala:349` and preceding evaluator body. |
| OP-0xD4 / OP-0xD5; A053/A054/I003/I005 | P(1,10,128) is the declared AST descriptor. Embedded-script substitution uses measured **2 BC per script byte**, not that descriptor as an interchangeable formula. `I/sigmastate/interpreter/Interpreter.scala:99`; register substitution calls it at `I/org/ergoplatform/ErgoLikeInterpreter.scala:17`. |
| EVAL-deferred-charge-on-exception; E012/E013 | Fixed/type-based/known-length helpers charge before the body. Unknown-length `addSeqCost` runs the body first and then charges; a throw skips the outer deferred charge, leaving earlier nested charges. `I/sigmastate/interpreter/CErgoTreeEvaluator.scala:296`, `:333`, `:370`, `:399`. |
| EVAL-eq-coll-descriptor; E025–E031 | Specialized array equality counts **actually compared items**. `D/sigma/data/DataValueComparer.scala:159`, especially line 173. String equality instead uses the Short-array descriptor over full equal string length at line 404. |
| EVAL-eq-coll-sigmaprop-descriptor | No specialized P(15,5,1) SigmaProp collection descriptor exists. Generic collection recursion applies when descriptor lookup misses at `D/sigma/data/DataValueComparer.scala:229`. |
| METHOD-global-powHit; M121/E039 | Exact formula: `500 + (k+1)*((msg.length+nonce.length+h.length)/128+1)*7`. Intermediate arithmetic is ordinary Int; `N` is absent. `D/sigma/ast/CostKind.scala:79`. |
| METHOD-global-serialize-writer-callbacks; E042–E047 | Plain `putUInt` adds **no callback**; metadata `putUInt` adds F(3). Bits use bit count; short strings use character count. `putChunk` charges after writing, unlike precharged byte-array writes. See F. |
| TX-storage-rent; T010/T011 | StorageContractCost is **50 BC**. Exceptions recover into ordinary verification; a successfully returned `false` does not trigger `recoverWith`. Monetary storage fee is not computational cost. `EW/org/ergoplatform/wallet/interpreter/ErgoInterpreter.scala:81`, `:82`; `EW/org/ergoplatform/wallet/protocol/Constants.scala:21`. |
| TX-scripts-skipped-pairing; B003 | At `currentHeight <= checkpointHeight`, Scala bypasses **transaction execution/cost validation** and returns `Valid(0L)`, not merely script verification. `EN/org/ergoplatform/nodeView/state/ErgoState.scala:135`. |
| BLOCK-param-voting; B011 | 16,384 is a threshold tested against the **current** maxBlockCost before lowering, not a clamp on the proposed value. Generic step is `max(1,current/100)`. `EC/org/ergoplatform/settings/Parameters.scala:170`, `:176`, `:354`. |
| EVAL-avl-cost-height | Only delegation to `rootNodeHeight` is verified from the supplied source. Do not mechanically promote the ledger’s invalid-metadata/digest-byte rule to source-verified truth without the dependency implementation or an independent fixture. |

### Agreements worth preserving

- Threshold formula is `P(10,10,1;c) + n*P(3,3,1;c) + 15 + Σchildren`, `c=n-k`. At `c=0`, the non-child subtotal is **25+3n**, without forcing one chunk. Source: `I/sigmastate/interpreter/Interpreter.scala:580` and `I/sigmastate/SigSerializer.scala:142`, `:151`. This verifies the Scala side of the ledger’s suspicion; it does not independently verify current Rust behavior.
- Crypto leaves are **3980/7140 JIT**, conjunction/disjunction overhead is **15 JIT**, and crypto subtotal truncates separately from evaluator subtotal.
- FlatMap counts output length; zip and startsWith/endsWith count receiver length; updateMany counts receiver length. Existing ledger formulas agree.
- Transaction initialization and token formulas agree. Token intermediate arithmetic is checked Int; cumulative transaction/block arithmetic is checked Long.
- All three transaction cumulative-cost comparisons allow equality: `ErgoTransaction.scala:394`, `:200`, `:159`.
- The executable verification path uses direct evaluation. The historical AOT discussion does not establish a second active accounting implementation in this checkout.

## E. Expand VERSION-branches-G007-G020

Replace the group row with these **14** rows. G010 intentionally overlaps the existing `VERSION-selfboxindex-bug`; retain that relationship explicitly instead of counting it as another charge.

```toml
{id="VERSION-G007", cat="VERSION", scala="interpreter/shared/src/main/scala/sigmastate/interpreter/CErgoTreeEvaluator.scala:150", rust="unverified", layer="L1,L2", state="OPEN", tests=[], note="G007: failed AVL insert throws for tree version <3; tree version >=3 uses the failed operation result. Per-entry cost has already been charged. Later digest/result work can differ. Matching branch also exists at interpreter/shared/src/main/scala/sigmastate/eval/Extensions.scala:99."}
```

```toml
{id="VERSION-G008", cat="VERSION", scala="data/shared/src/main/scala/sigma/serialization/ErgoTreeSerializer.scala:330", rust="unverified", layer="L1,L2", state="OPEN", tests=[], note="G008: JIT activation selects SubstConstants serialization implementation; tree version >=3 additionally preserves the original size field when the header has the size bit at ErgoTreeSerializer.scala:369. Base substitution descriptor is unchanged; produced bytes and later costs can differ."}
```

```toml
{id="VERSION-G009", cat="VERSION", scala="data/shared/src/main/scala/sigma/ast/trees.scala:39", rust="unverified", layer="L1,L2", state="OPEN", tests=[], note="G009: BoolToSigmaProp charges FixedCost(15) before activation-dependent conversion. Before JIT activation a SigmaProp-valued input is permitted; after activation Boolean casting is required. Test result, exception and subsequent crypto proposition."}
```

```toml
{id="VERSION-G010", cat="VERSION", scala="interpreter/shared/src/main/scala/sigmastate/eval/CContext.scala:51", rust="unverified", layer="L1,L2", state="OPEN", tests=[], note="G010: selfBoxIndex returns -1 before activatedScriptVersion 2 and the actual self index afterward. Accessor cost remains 20. Same obligation as existing VERSION-selfboxindex-bug; no additional charge."}
```

```toml
{id="VERSION-G011", cat="VERSION", scala="data/shared/src/main/scala/sigma/data/CSigmaDslBuilder.scala:117", rust="unverified", layer="L1,L2", state="OPEN", tests=[], note="G011: xorOf uses old distinct-value semantics before JIT activation and XOR semantics afterward. No independent tariff here; changed Boolean result can change later charged execution."}
```

```toml
{id="VERSION-G012", cat="VERSION", scala="core/shared/src/main/scala/sigma/data/CollsOverArrays.scala:50", rust="unverified", layer="L1,L2", state="OPEN", tests=[], note="G012: JIT activation fixes array concatenation; pairColl at CollsOverArrays.scala:184 truncates sides to matching lengths under JIT. Append and Zip prices remain unchanged, but representation, lengths, exceptions and later costs can differ."}
```

```toml
{id="VERSION-G013", cat="VERSION", scala="core/shared/src/main/scala/sigma/data/CollsOverArrays.scala:148", rust="unverified", layer="L1,L2", state="OPEN", tests=[], note="G013: tree version >=3 permits PairColl versus CollOverArray equality in both representation directions; second branch is CollsOverArrays.scala:282. No new descriptor; changed equality can change short-circuiting and later execution."}
```

```toml
{id="VERSION-G014", cat="VERSION", scala="core/shared/src/main/scala/sigma/ast/SType.scala:412", rust="unverified", layer="L1,L2", state="OPEN", tests=[], note="G014: tree version >=3 changes BigInt/UnsignedBigInt conversion cases at SType.scala:412,435,460,487,512,524 and enforces signed BigInt bitLength <=255 at core/shared/src/main/scala/sigma/data/CBigInt.scala:18. Cast tariff remains target-based 10 or 30; results and exceptions affect continuation."}
```

```toml
{id="VERSION-G015", cat="VERSION", scala="data/shared/src/main/scala/sigma/serialization/ValueSerializer.scala:157", rust="unverified", layer="L1,L2", state="OPEN", tests=[], note="G015: pre-v3 serialization strips a leading Upcast; tree version >=3 preserves it. A preserved cast may later incur its 10/30 cost when executed. Distinct from DeserializationSigmaBuilder automatic operand-upcast insertion."}
```

```toml
{id="VERSION-G016", cat="VERSION", scala="data/shared/src/main/scala/sigma/serialization/MethodCallSerializer.scala:53", rust="unverified", layer="L1,L2", state="OPEN", tests=[], note="G016: versioned method parsing/type-argument handling and ByIndex parsing determine the reconstructed charged expression. ByIndex tree-version branch is data/shared/src/main/scala/sigma/serialization/transformers/ByIndexSerializer.scala:29. No separate parser tariff is introduced by these branches."}
```

```toml
{id="VERSION-G017", cat="VERSION", scala="core/shared/src/main/scala/sigma/serialization/CoreDataSerializer.scala:39", rust="unverified", layer="L1,L2", state="OPEN", tests=[], note="G017: tree version >=3 enables unsigned and Option data branches at CoreDataSerializer.scala:39,78,118,140 and Header branches at data/shared/src/main/scala/sigma/serialization/DataSerializer.scala:19,39. Global serialization callback totals and deserializeTo success depend on represented data."}
```

```toml
{id="VERSION-G018", cat="VERSION", scala="core/shared/src/main/scala/sigma/serialization/TypeSerializer.scala:19", rust="unverified", layer="L1,L2", state="OPEN", tests=[], note="G018: A6 selects primitive/type validation rules at TypeSerializer.scala:19,228; T3 selects function serialization/deserialization and embedded type tables at :111,211,258. Related predefined-type and unsigned checks are core/shared/src/main/scala/sigma/ast/SType.scala:117,167,194. Preserve each local activation versus tree-version condition; no independent type-validation tariff."}
```

```toml
{id="VERSION-G019", cat="VERSION", scala="data/shared/src/main/scala/sigma/ast/methods.scala:131", rust="unverified", layer="L1,L2", state="OPEN", tests=[], note="G019: A6 selects CheckAndGetMethodV6. Replaced rules 1011,1007,1008 cease being tolerated as soft forks under A6 at core/shared/src/main/scala/sigma/validation/SigmaValidationSettings.scala:60. This can turn baseline-cost soft-fork acceptance into rejection."}
```

```toml
{id="VERSION-G020", cat="VERSION", scala="data/shared/src/main/scala/org/ergoplatform/validation/ValidationRules.scala:233", rust="unverified", layer="L1,L2", state="OPEN", tests=[], note="G020: A6 selects v6 validation-rule sets; core selection is core/shared/src/main/scala/sigma/validation/ValidationRules.scala:229. trySoftForkable at :248 handles recognized ValidationExceptions according to settings; it does not generally forgive ArithmeticException or CostLimitException."}
```

## F. Expand METHOD-global-serialize-writer-callbacks

Replace the callback group with these **six** rows. Retain `METHOD-global-serialize` for method identity and the F(10) writer startup.

The inherited unsigned-byte path reaches the external `Writer` superclass through `CoreByteWriter.scala:37`. The supplied checkouts establish this delegation, but do not contain that external superclass implementation. Keep aggregate unsigned-byte callback behavior open for an independent fixture; do not invent a separate F(3) unsigned-byte callback.

```toml
{id="METHOD-global-serialize-E042", cat="METHOD", scala="data/shared/src/main/scala/sigma/serialization/SigmaByteWriter.scala:45", rust="unverified", layer="L1,L2", state="OPEN", tests=[], note="E042: explicit byte/Boolean and option-tag callbacks each add FixedCost(1). Sites are SigmaByteWriter.scala:45,50,61,66,171; descriptor at :241. Option content is charged through nested writes. Metadata putUByte at :56 adds no explicit callback and delegates through CoreByteWriter; test inherited unsigned-byte callback behavior separately."}
```

```toml
{id="METHOD-global-serialize-E043", cat="METHOD", scala="data/shared/src/main/scala/sigma/serialization/SigmaByteWriter.scala:72", rust="unverified", layer="L1,L2", state="OPEN", tests=[], note="E043: signed Short, Int and Long writes add FixedCost(3) per explicit callback, including metadata overloads. Sites :72,77,94,99,115,120; PutSignedNumericCost at :256. Costs are per write operation, not encoded byte count."}
```

```toml
{id="METHOD-global-serialize-E044", cat="METHOD", scala="data/shared/src/main/scala/sigma/serialization/SigmaByteWriter.scala:83", rust="unverified", layer="L1,L2", state="OPEN", tests=[], note="E044: UShort, metadata UInt and ULong writes add FixedCost(3) at :83,88,109,126,131; descriptor at :248. Plain putUInt at :105 delegates without a callback. Unsigned-byte inheritance is not an explicit unsigned-numeric three-unit callback."}
```

```toml
{id="METHOD-global-serialize-E045", cat="METHOD", scala="data/shared/src/main/scala/sigma/serialization/SigmaByteWriter.scala:38", rust="unverified", layer="L1,L2", state="OPEN", tests=[], note="E045: chunk and byte-array writes use PerItemCost(3,1,1;n)=3+n. putChunk at :38 writes first, then charges the actual length increase at :41; byte-array overloads :137,142,147 charge their requested lengths before delegation; putShortBytes at :155 uses n=2. Descriptor at :262."}
```

```toml
{id="METHOD-global-serialize-E046", cat="METHOD", scala="data/shared/src/main/scala/sigma/serialization/SigmaByteWriter.scala:160", rust="unverified", layer="L1,L2", state="OPEN", tests=[], note="E046: bit-array overloads at :160,165 charge PerItemCost(3,1,1;number of bits). putShortString at :176 charges the same descriptor over String.length, not encoded-byte length. Verify zero-length and encoding-boundary cases."}
```

```toml
{id="METHOD-global-serialize-E047", cat="METHOD", scala="data/shared/src/main/scala/sigma/serialization/SigmaByteWriter.scala:181", rust="unverified", layer="L1,L2", state="OPEN", tests=[], note="E047: putType, putValue and putValues at :181,188,197,204,214 delegate to constituent serialization with no extra standalone type/value fee. Plain putValues uses uncharged plain putUInt for count; metadata putValues uses charged metadata putUInt. Aggregate cost must follow actual overloads and nested callbacks."}
```

## G. Existing Scala fields lacking file:line

**228 entries.** Expand the source prefixes using the key above. `NOT FOUND IN SCALA` must remain an explicit finding; do not fabricate an anchor for an obligation contradicted by source.

For grouped obligations, the listed anchor is an entry point; section A identifies their remaining enumeration anchors. For absence rows, the registry anchor verifies absence rather than an executable tariff.

```text
OP-0x72 → D/sigma/ast/values.scala:971
OP-0x73 → D/sigma/ast/values.scala:421
OP-0x74 → D/sigma/ast/trees.scala:655
OP-0x7A → D/sigma/ast/trees.scala:466
OP-0x7B → D/sigma/ast/trees.scala:506
OP-0x7C → D/sigma/ast/trees.scala:486
OP-0x7D → D/sigma/ast/trees.scala:442
OP-0x7E → D/sigma/ast/trees.scala:418
OP-0x7F → D/sigma/ast/values.scala:747
OP-0x80 → D/sigma/ast/values.scala:758
OP-0x81 → D/sigma/serialization/ValueSerializer.scala:42
OP-0x82 → D/sigma/ast/values.scala:712
OP-0x83 → D/sigma/ast/values.scala:878
OP-0x85 → D/sigma/ast/values.scala:890
OP-0x86 → D/sigma/ast/values.scala:815
OP-0x87-0x8B → D/sigma/serialization/ValueSerializer.scala:47
OP-0x8C → D/sigma/ast/transformers.scala:314
OP-0x8F → D/sigma/ast/trees.scala:1106
OP-0x90 → D/sigma/ast/trees.scala:1133
OP-0x91 → D/sigma/ast/trees.scala:1160
OP-0x92 → D/sigma/ast/trees.scala:1187
OP-0x93 → D/sigma/ast/trees.scala:1214
OP-0x94 → D/sigma/ast/trees.scala:1234
OP-0x95 → D/sigma/ast/trees.scala:1373
OP-0x96 → D/sigma/ast/trees.scala:292
OP-0x97 → D/sigma/ast/trees.scala:222
OP-0x98 → D/sigma/ast/trees.scala:328
OP-0x99 → D/sigma/ast/trees.scala:767
OP-0x9A → D/sigma/ast/trees.scala:752
OP-0x9B → D/sigma/ast/trees.scala:1016
OP-0x9C → D/sigma/ast/trees.scala:782
OP-0x9D → D/sigma/ast/trees.scala:797
OP-0x9E → D/sigma/ast/trees.scala:814
OP-0x9F → D/sigma/ast/trees.scala:1046
OP-0xA0 → D/sigma/ast/trees.scala:1067
OP-0xA1 → D/sigma/ast/trees.scala:829
OP-0xA2 → D/sigma/ast/trees.scala:844
OP-0xA3 → D/sigma/ast/values.scala:1453
OP-0xA4 → D/sigma/ast/values.scala:1466
OP-0xA5 → D/sigma/ast/values.scala:1480
OP-0xA6 → D/sigma/ast/values.scala:1495
OP-0xA7 → D/sigma/ast/values.scala:1509
OP-0xAC → D/sigma/ast/values.scala:1439
OP-0xAD → D/sigma/ast/transformers.scala:52
OP-0xAE → D/sigma/ast/transformers.scala:170
OP-0xAF → D/sigma/ast/transformers.scala:197
OP-0xB0 → D/sigma/ast/transformers.scala:236
OP-0xB1 → D/sigma/ast/transformers.scala:373
OP-0xB2 → D/sigma/ast/transformers.scala:285
OP-0xB3 → D/sigma/ast/transformers.scala:74
OP-0xB4 → D/sigma/ast/transformers.scala:106
OP-0xB5 → D/sigma/ast/transformers.scala:134
OP-0xB6 → D/sigma/ast/trees.scala:89
OP-0xB7 → D/sigma/ast/trees.scala:1336
OP-0xC1 → D/sigma/ast/transformers.scala:394
OP-0xC2 → D/sigma/ast/transformers.scala:420
OP-0xC3 → D/sigma/ast/transformers.scala:440
OP-0xC4 → D/sigma/ast/transformers.scala:460
OP-0xC5 → D/sigma/ast/transformers.scala:479
OP-0xC6 → D/sigma/ast/transformers.scala:500
OP-0xC7 → D/sigma/ast/transformers.scala:527
OP-0xCB → D/sigma/ast/trees.scala:582
OP-0xCC → D/sigma/ast/trees.scala:604
OP-0xCD → D/sigma/ast/trees.scala:73
OP-0xCE → D/sigma/ast/trees.scala:114
OP-0xCF → D/sigma/ast/transformers.scala:328
OP-0xD0 → D/sigma/ast/transformers.scala:349
OP-0xD1 → D/sigma/ast/trees.scala:55
OP-0xD4 → D/sigma/ast/transformers.scala:558
OP-0xD5 → D/sigma/ast/transformers.scala:571
OP-0xD6 → D/sigma/ast/values.scala:935
OP-0xD7 → D/sigma/ast/values.scala:943
OP-0xD8 → D/sigma/ast/values.scala:1013
OP-0xD9 → D/sigma/ast/values.scala:1070
OP-0xDA → D/sigma/ast/values.scala:1253
OP-0xDB → D/sigma/ast/values.scala:1391
OP-0xDC → D/sigma/ast/values.scala:1371
OP-0xDD → D/sigma/ast/values.scala:1542
OP-0xDF → D/sigma/serialization/ValueSerializer.scala:42
OP-0xE3 → D/sigma/ast/transformers.scala:589
OP-0xE4 → D/sigma/ast/transformers.scala:611
OP-0xE5 → D/sigma/ast/transformers.scala:649
OP-0xE6 → D/sigma/ast/transformers.scala:667
OP-0xE7-0xE9 → D/sigma/ast/trees.scala:962
OP-0xEA → D/sigma/ast/trees.scala:149
OP-0xEB → D/sigma/ast/trees.scala:180
OP-0xEC → D/sigma/ast/trees.scala:1257
OP-0xED → D/sigma/ast/trees.scala:1280
OP-0xEE → D/sigma/ast/trees.scala:530
OP-0xEF → D/sigma/ast/trees.scala:1391
OP-0xF0 → D/sigma/ast/trees.scala:894
OP-0xF1 → D/sigma/ast/trees.scala:906
OP-0xF2 → D/sigma/ast/trees.scala:926
OP-0xF3 → D/sigma/ast/trees.scala:929
OP-0xF4 → D/sigma/ast/trees.scala:1300
OP-0xF5 → D/sigma/ast/trees.scala:932
OP-0xF6 → D/sigma/ast/trees.scala:935
OP-0xF7 → D/sigma/ast/trees.scala:938
OP-0xF8 → D/sigma/ast/trees.scala:941
OP-0xFE → D/sigma/ast/values.scala:1525
OP-0xFF → D/sigma/ast/trees.scala:253
EVAL-const-inline → D/sigma/ast/values.scala:380
EVAL-hasdeserialize-fork → I/sigmastate/interpreter/Interpreter.scala:218
EVAL-addtoenv → D/sigma/ast/values.scala:1047
EVAL-numeric-cast → D/sigma/ast/CostKind.scala:60
EVAL-arith-bigint → D/sigma/ast/trees.scala:733
EVAL-eq-prim → D/sigma/data/DataValueComparer.scala:27
EVAL-eq-matchtype → D/sigma/data/DataValueComparer.scala:22
EVAL-eq-tuple → D/sigma/data/DataValueComparer.scala:39
EVAL-eq-groupelement → D/sigma/data/DataValueComparer.scala:44
EVAL-eq-bigint → D/sigma/data/DataValueComparer.scala:48
EVAL-eq-avltree → D/sigma/data/DataValueComparer.scala:52
EVAL-eq-box → D/sigma/data/DataValueComparer.scala:56
EVAL-eq-option → D/sigma/data/DataValueComparer.scala:61
EVAL-eq-preheader → D/sigma/data/DataValueComparer.scala:65
EVAL-eq-header → D/sigma/data/DataValueComparer.scala:69
EVAL-eq-coll-descriptor → D/sigma/data/DataValueComparer.scala:74
EVAL-eq-coll-sigmaprop-descriptor → NOT FOUND IN SCALA
EVAL-eq-coll-fallback → D/sigma/data/DataValueComparer.scala:183
EVAL-eq-tokens → D/sigma/data/DataValueComparer.scala:183
EVAL-eq-sigmaboolean → D/sigma/data/DataValueComparer.scala:255
EVAL-eq-boxcollection → D/sigma/data/DataValueComparer.scala:122
EVAL-max-depth → NOT FOUND IN SCALA
EVAL-avl-cost-height → I/sigmastate/eval/CAvlTreeVerifier.scala:24
METHOD-context-dataInputs → D/sigma/ast/methods.scala:1739
METHOD-context-headers → D/sigma/ast/methods.scala:1740
METHOD-context-preHeader → D/sigma/ast/methods.scala:1741
METHOD-context-selfBoxIndex → D/sigma/ast/methods.scala:1746
METHOD-context-lastBlockUtxoRootHash → D/sigma/ast/methods.scala:1747
METHOD-context-minerPubKey → D/sigma/ast/methods.scala:1748
METHOD-context-getVarFromInput → D/sigma/ast/methods.scala:1755
METHOD-header-props → D/sigma/ast/methods.scala:1797
METHOD-header-checkPow → D/sigma/ast/methods.scala:1815
METHOD-preheader-props → D/sigma/ast/methods.scala:1841
METHOD-global-groupGenerator → D/sigma/ast/methods.scala:1871
METHOD-global-xor → D/sigma/ast/methods.scala:1876
METHOD-global-serialize → D/sigma/ast/methods.scala:1957
METHOD-global-deserializeTo → D/sigma/ast/methods.scala:1906
METHOD-global-fromBigEndianBytes → D/sigma/ast/methods.scala:1925
METHOD-global-encodeNbits → D/sigma/ast/methods.scala:1938
METHOD-global-decodeNbits → D/sigma/ast/methods.scala:1943
METHOD-global-powHit → D/sigma/ast/methods.scala:1884
METHOD-global-some → D/sigma/ast/methods.scala:1986
METHOD-global-none → D/sigma/ast/methods.scala:1994
METHOD-box-tokens → D/sigma/ast/methods.scala:1349
METHOD-box-getReg → D/sigma/ast/methods.scala:1329
METHOD-avl-props → D/sigma/ast/methods.scala:1391
METHOD-avl-updateOperations → D/sigma/ast/methods.scala:1469
METHOD-avl-updateDigest → D/sigma/ast/methods.scala:1657
METHOD-avl-contains → D/sigma/ast/methods.scala:1477
METHOD-avl-get → D/sigma/ast/methods.scala:1527
METHOD-avl-getMany → D/sigma/ast/methods.scala:1553
METHOD-avl-insert → D/sigma/ast/methods.scala:1577
METHOD-avl-update → D/sigma/ast/methods.scala:1603
METHOD-avl-insertOrUpdate → D/sigma/ast/methods.scala:1671
METHOD-avl-remove → D/sigma/ast/methods.scala:1630
METHOD-coll-indices → D/sigma/ast/methods.scala:954
METHOD-coll-reverse → D/sigma/ast/methods.scala:1126
METHOD-coll-indexOf → D/sigma/ast/methods.scala:1070
METHOD-coll-zip → D/sigma/ast/methods.scala:1105
METHOD-coll-get → D/sigma/ast/methods.scala:1183
METHOD-coll-flatMap → D/sigma/ast/methods.scala:982
METHOD-coll-patch → D/sigma/ast/methods.scala:1013
METHOD-coll-updated → D/sigma/ast/methods.scala:1033
METHOD-coll-updateMany → D/sigma/ast/methods.scala:1053
METHOD-option-map → D/sigma/ast/methods.scala:775
METHOD-option-filter → D/sigma/ast/methods.scala:784
METHOD-groupelement-getEncoded → D/sigma/ast/methods.scala:642
METHOD-groupelement-negate → D/sigma/ast/methods.scala:672
METHOD-groupelement-exp → D/sigma/ast/methods.scala:647
METHOD-numeric-toBytes-toBits → D/sigma/ast/methods.scala:311
METHOD-numeric-bitwise → D/sigma/ast/methods.scala:355
METHOD-numeric-shift → D/sigma/ast/methods.scala:421
METHOD-bigint-toUnsigned → D/sigma/ast/methods.scala:546
METHOD-bigint-toUnsignedMod → D/sigma/ast/methods.scala:553
METHOD-ubigint-toSigned → D/sigma/ast/methods.scala:609
METHOD-ubigint-bitwise → D/sigma/ast/methods.scala:370
METHOD-ubigint-shift → D/sigma/ast/methods.scala:421
METHOD-ubigint-modInverse → D/sigma/ast/methods.scala:576
METHOD-ubigint-plusMod → D/sigma/ast/methods.scala:585
METHOD-ubigint-subtractMod → D/sigma/ast/methods.scala:591
METHOD-ubigint-multiplyMod → D/sigma/ast/methods.scala:597
METHOD-ubigint-mod → D/sigma/ast/methods.scala:603
METHOD-unclaimed-inventory → D/sigma/ast/methods.scala:63
INTERP-init-cost → EW/org/ergoplatform/wallet/interpreter/ErgoInterpreter.scala:96
INTERP-eval-sigmaprop-constant → I/sigmastate/interpreter/Interpreter.scala:215
INTERP-deser-subst → I/sigmastate/interpreter/Interpreter.scala:246
INTERP-crypto-dlog → I/sigmastate/interpreter/Interpreter.scala:537
INTERP-crypto-dht → I/sigmastate/interpreter/Interpreter.scala:543
INTERP-crypto-conjunction → I/sigmastate/UnprovenTree.scala:220
INTERP-crypto-trunc → I/sigmastate/interpreter/Interpreter.scala:280
INTERP-jitcost-bounds → D/sigma/ast/JitCost.scala:9
INTERP-toblockcost → D/sigma/ast/JitCost.scala:29
ROUND-snap-per-input → I/sigmastate/interpreter/CErgoTreeEvaluator.scala:587
ROUND-crypto-per-input → I/sigmastate/interpreter/Interpreter.scala:280
ROUND-perItem-chunking → D/sigma/ast/CostKind.scala:26
ORDER-init-token → EC/org/ergoplatform/modifiers/mempool/ErgoTransaction.scala:394
ORDER-pre-v3-upcast → D/sigma/ast/SigmaBuilder.scala:750
ORDER-blockvalue-valdef → D/sigma/ast/values.scala:999
ORDER-constplaceholder → D/sigma/ast/values.scala:409
ORDER-hof-charge → D/sigma/ast/transformers.scala:40
ORDER-comparison-charge → D/sigma/ast/trees.scala:1092
ORDER-bitop-charge-then-reject → NOT FOUND IN SCALA
ORDER-crypto-before-verify → I/sigmastate/interpreter/Interpreter.scala:372
LIMIT-tx-start → EC/org/ergoplatform/modifiers/mempool/ErgoTransaction.scala:391
TX-init-formula → EC/org/ergoplatform/modifiers/mempool/ErgoTransaction.scala:370
TX-token-cost → EC/org/ergoplatform/modifiers/mempool/ErgoTransaction.scala:191
TX-storage-rent → EW/org/ergoplatform/wallet/interpreter/ErgoInterpreter.scala:72
TX-scripts-skipped-pairing → EN/org/ergoplatform/nodeView/state/ErgoState.scala:135
TX-voted-params → EC/org/ergoplatform/settings/Parameters.scala:48
TX-accumulator-shared → EC/org/ergoplatform/modifiers/mempool/ErgoTransaction.scala:153
BLOCK-per-tx-cap → EC/org/ergoplatform/modifiers/mempool/ErgoTransaction.scala:391
BLOCK-accum-equiv → EN/org/ergoplatform/nodeView/state/ErgoState.scala:140
BLOCK-parallel-equiv → NOT FOUND IN SCALA
BLOCK-overflow → EC/org/ergoplatform/modifiers/mempool/ErgoTransaction.scala:370
BLOCK-rejection-state-unchanged → EN/org/ergoplatform/nodeView/state/UtxoState.scala:209
VERSION-pre-v3-upcast → D/sigma/ast/SigmaBuilder.scala:750
VERSION-v3-bool-root → NOT FOUND IN SCALA
VERSION-v6-method-gate → D/sigma/ast/methods.scala:79
VERSION-selfboxindex-bug → I/sigmastate/eval/CContext.scala:51
VERSION-tree-version-gate → I/sigmastate/interpreter/Interpreter.scala:304
VERSION-hardening-creation-height → EC/org/ergoplatform/modifiers/mempool/ErgoTransaction.scala:384
VERSION-v6-lazy-defaults → D/sigma/ast/transformers.scala:261
EVAL-deferred-charge-on-exception → I/sigmastate/interpreter/CErgoTreeEvaluator.scala:399
INTERP-embedded-script-deser → I/sigmastate/interpreter/Interpreter.scala:81
VERSION-subst-retention → I/sigmastate/interpreter/Interpreter.scala:246
VERSION-branches-G007-G020 → I/sigmastate/interpreter/CErgoTreeEvaluator.scala:150
METHOD-global-serialize-writer-callbacks → D/sigma/serialization/SigmaByteWriter.scala:45
```

The nine existing rows already containing a Scala file:line were excluded from G: `METHOD-coll-startsEndsWith`, `INTERP-crypto-threshold`, `INTERP-costlimit-op`, `LIMIT-per-input`, `LIMIT-block-sum`, `BLOCK-sum-op`, `VERSION-jit-activation`, `BLOCK-param-voting`, and `BLOCK-overflow-fixture`.

Apply section D’s semantic corrections alongside anchor updates. An anchor-only replacement would otherwise preserve several source-contradicted obligations.

## H. Applied result and controller resolutions

All 363 entries map to specific obligations; 281 ledger rows remain after 26 additions and replacement of two placeholders with 20 expanded rows. No conformance row was closed by this source audit. Existing CLOSED and N-A states are preserved; additions have the draft's OPEN/N-A states. Section D corrections are stored verbatim in Scala fields with expanded source prefixes, except the five controller-resolved claims below. Sections B/E/F list the applied additions; section G records the original anchor inventory.

- VERSION-v3-bool-root: rule 1001 CheckDeserializedScriptIsSigmaProp, ValidationRules.scala:40-50, rejects non-SigmaProp roots for ALL tree versions at deserialization. ErgoTreeSerializer.scala:173 applies it with checkType on the consensus path. Rust mirrors it in ergo-ser/src/ergo_tree/type_infer.rs. Obligation: parse-time RejectScript on both sides with no cost; OPEN for L2. Stale reduction comments are corrected, with no behavior change.
- ORDER-bitop-charge-then-reject: Value.eval at values.scala:101 throws WITHOUT charging. Rust errors.rs:41-44 charges Fixed(1) first. Both sides RejectScript. SUSPECT: Rust overcharges 1 JIT before rejecting; consensus-neutral; fix = drop the add_cost. OPEN; no behavior change in this task.
- EVAL-eq-coll-sigmaprop-descriptor: DataValueComparer.scala:229-235 uses equalColls fallback; no specialized Scala descriptor exists. Rust typed (15,5,1) path is SUSPECT; OPEN.
- EVAL-max-depth: N-A, Rust-only guard; values.scala:113 is an absence-verification anchor.
- BLOCK-parallel-equiv: OPEN Rust-internal sequential/parallel equivalence obligation under design section 4; ErgoState.scala:140 anchors the sequential reference.

External BatchAVLVerifier height details and inherited Writer unsigned-byte behavior remain explicit OPEN fixture obligations, not missing inventory mappings. A resolved inventory does not claim those runtime behaviors are proven.

### Spot verification

15 anchors were inspected against the pinned read-only checkouts; none was wrong: values.scala:409,935; trees.scala:962,1106; CostKind.scala:60; methods.scala:647,656; transformers.scala:40; DataValueComparer.scala:183,229; Interpreter.scala:246; Parameters.scala:170; ErgoState.scala:135; validation/ValidationRules.scala:40; ErgoTreeSerializer.scala:173. Surrounding lines confirmed lookup-before-charge, unsupported standalone ValDef, declared modular F(1), type-based comparison pricing, target-based casts, signed/unsigned method IDs, mapper-before-overhead, generic equality fallback, substitution retention, current-value voting threshold, checkpoint bypass, and parse-time root rejection.

### Repeatable diff

Run `python3 scripts/cost-ledger-diff.py`. The tracked scala-enumeration.md is a byte-for-byte copy of the supplied blind enumeration (the original dev-docs path is ignored). inventory-map.json records explicit many-to-many counterparts, reviewed enumeration cells, and reviewed Scala fields. Ledger-only entries retain source-backed findings from section C. Names normalize opcode hex, SType.method spellings, Markdown decoration, and whitespace.

The three discrepancy lists are enumeration-only, ledger-only, and matched-with-different-constant. Empty lists produce no output and exit 0. The third list conservatively flags any changed audited formula, gating, anchor, or semantic description for source review: it does not attempt symbolic equivalence of arbitrary Scala formulas. New or deleted rows are detected in either direction. A mapping snapshot is inventory evidence only and never an independent cost oracle or grounds to close a ledger row. Update reviewed snapshots only after resolving differences against the pinned source and documenting the resolution here.

Status: RESOLVED
