# Known consensus-divergence catalog (rediscovery suite)

25 past Rust-vs-Scala divergences, mined from `dev-docs/` incidents + git log,
fix locations verified on current `main`. This is the **generator-acceptance
gate**: a generator that cannot rediscover its wire-reachable bugs is rejected.

Paths relative to worktree root. `WR` = wire-reachable (a byte-level generator
can hit it) · `SD` = state-dependent (replay-driver only).

| # | id | class | surface | reach | fix commit | fix location |
|---|----|-------|---------|-------|-----------|--------------|
| 1 | utf8-stypevar-sstring | reject-valid + accept-invalid | ergo_tree (FunDef/SString) | WR | `aaf0956` | ergo-ser/src/sigma_type.rs:435 (`jvm_utf8::decode`), sigma_value.rs |
| 2 | register-provenance-1808895 | reject-valid stall | box register / bytesWithNoRef | SD | `944de9c` | ergo-sigma/src/evaluator/opcodes/box_context.rs:213 |
| 3 | deser-subst-cost-reserialized | reject-valid (cost) | reduction cost | SD | `35ed249` | ergo-sigma/src/reduce.rs:211 (`self_box.script_bytes.len()`) |
| 4 | off-curve-group-element | accept-invalid | tx deser / GE parse | WR | `0f16db7` | ergo-validation/src/tx/ge.rs:22, ergo-sigma dispatch.rs:257 |
| 5 | checkv6type-register-rule-1019 | accept-invalid | box register parse | WR | `6db49c0` | ergo-ser/src/register.rs:141 (`type_has_v6_register_type`) |
| 6 | avl-verifier-panic | DoS / availability | AVL proof verify | WR | `78830ba` | ergo-sigma/src/avl.rs:82 (`catch_unwind`+poison) |
| 7 | fork-vote-gate-rule-407 | accept-invalid | block header / voting | SD | `cb0e450` | ergo-validation/src/block.rs:478 |
| 8 | signed-header-version-byte | accept-invalid + canonical | header wire grammar | WR | `b914866`,`449c362` | ergo-ser/src/header.rs:68 (`version_gt` signed cast) |
| 9 | check-header-size-bit-rule-1012 | accept-invalid | box script parse | WR | `a1df24f` | ergo-ser/src/ergo_tree.rs:115 → ergo_box.rs |
| 10 | adproofs-data-input-lookup | reject-valid (mined block) | ADProofs gen (mining) | SD | `56fa480` | ergo-state/src/store/dry_run.rs:86 |
| 11 | eip27-reemission-not-enforced | accept-invalid | tx monetary (block) | SD | `dbdb143` | ergo-validation/src/tx/reemission.rs:100 |
| 12 | relation2-0x85-noncanonical | canonical → cost | ergo_tree serialize | WR | `00ad30a` | ergo-ser/src/opcode/write.rs:9 (`relation2_bool_pair`) |
| 13 | atleast-trivial-fold-and-cap | DoS / accept-invalid | script eval / atLeast | WR | `fa97cfc`,`47c493f` | ergo-sigma/src/evaluator/opcodes/sigma.rs:433,467 |
| 14 | fundef-ntpeargs-signed-byte | accept-invalid | ergo_tree opcode parse | WR | `4c54531` | ergo-ser/src/opcode/parse.rs:179 |
| 15 | coll-equality-no-short-circuit | reject-valid (cost) | JIT cost / Coll EQ | SD | `2af05f1` | ergo-sigma/src/evaluator (eq_with_cost_inner) |
| 16 | tokens-equality-cost | reject-valid (cost) | JIT cost / token EQ | SD | `d5e1d1b` | ergo-sigma/src/evaluator (eq_with_cost token arm) |
| 17 | ergotree-version-above-activated | accept-invalid | ergo_tree version gate | WR | `7264ba5` | ergo-ser/src/ergo_tree.rs:150 (`check_tree_version_supported`) |
| 18 | pre-v3-v6-method-dead-branch | accept-invalid | ergo_tree method resolve | WR | `e422238`,`7bcf246` | ergo-ser/src/ergo_tree.rs:183 (`check_resolvable_methods`) |
| 19 | ergotree-declared-size-vs-structural | reject-valid + accept-invalid | ergo_tree size-delim body | WR | `458e581`,`d2ec70f` | ergo-ser/src/ergo_tree.rs:950 |
| 20 | vlq-count-id-exact-vs-nonexact | reject-valid | ergo_tree VLQ count fields | WR | `7cc7941` | ergo-ser/src/ergo_tree.rs:1163 (`get_uint_to_i32`) |
| 21 | sunsignedbigint-embeddable-type | reject-valid (reversed) | ergo_tree type decode | WR | `1ef25c5` | ergo-ser/src/sigma_type.rs:601 (version gate on code 9) |
| 22 | qa-p0-erg-conservation-token-i64 | accept-invalid | tx monetary | SD | `a8dbdb5` | ergo-validation/src/tx/monetary.rs:91 |
| 23 | qa-p1-zero-output-token-positive | accept-invalid | tx structural | WR | `341fc61` | ergo-validation/src/tx/structural.rs:54 |
| 24 | unparsed-ergotree-reduces-to-true | accept-invalid (spend) | ergo_tree spend eval | SD | `ceae083` | ergo-ser/src/ergo_tree.rs (UnparsedErgoTree), ergo-sigma spend |
| 25 | rule-1001-non-sigmaprop-root | accept-invalid | ergo_tree root type | WR | `0028abf` | ergo-ser/src/ergo_tree.rs:217 (`check_sigma_prop_root`) |

## Re-injection recipes (WR bugs — the wire-generator gate)

These are the temporary scratch-branch patches the acceptance runner applies. Each
resurrects one bug; the generator must produce an input the differential flags.

- **#1 utf8-stypevar** — sigma_type.rs:435 `crate::jvm_utf8::decode(name_bytes)` →
  `String::from_utf8(name_bytes.to_vec()).map_err(|e| ReadError::InvalidData(e.to_string()))?`.
  Trigger byte: an ill-formed UTF-8 sequence (e.g. `ED A0 80`) in a FunDef STypeVar name.
- **#4 off-curve-GE** — remove `ge::validate_group_elements(...)` call in
  ergo-validation/src/tx/mod.rs. Trigger: 33-byte GE `02∥<x not on curve>`.
- **#5 checkv6type-register** — remove the `type_has_v6_register_type` gate in
  register.rs `read_registers`. Trigger: register typed `SOption(SInt)`.
- **#6 avl-panic** — replace `catch_unwind`-guarded construction in avl.rs with
  direct `BatchAVLVerifier` calls. Trigger: valid-shaped but wrong AVL proof (Lookup
  where Remove expected). Detection = **Rust panic** while JVM returns REJECT.
- **#8 signed-header-version** — header.rs:69 `(version as i8) > (threshold as i8)`
  → `version > threshold`. Trigger: header version byte `0x83` (=131, signed-neg).
- **#9 check-header-size-bit** — remove `check_header_size_bit(...)` in ergo_box.rs.
  Trigger: box script header `0x09` (v1, no size bit).
- **#12 relation2-0x85** — remove `relation2_bool_pair` compact-form detection in
  opcode/write.rs. Detection = canonical parse→serialize mismatch on a Relation2 over
  two boolean constants.
- **#13 atleast** — remove trivial-child fold / >255 cap in sigma.rs. Detection =
  panic or accept/reject mismatch.
- **#14 fundef-ntpeargs** — remove the signed-byte reject in opcode/parse.rs:179.
  Trigger: ErgoTree fragment `[header][0xD7][id-vlq][0x80]`.
- **#17 tree-version** — remove `check_tree_version_supported` in ergo_box.rs.
  Trigger: box header `0x21` (v4, has_size).
- **#18 pre-v3-v6-method** — remove `check_resolvable_methods` in ergo_box.rs.
  Trigger: pre-v3 tree with a MethodCall to a v6-only method id.
- **#19 declared-size** — revert ergo_tree.rs to `get_u32_exact`+`get_bytes(size)`.
  Trigger: size-delimited tree whose declared size ≠ actual body length.
- **#20 vlq-count-exact** — ergo_tree.rs constants-count `get_uint_to_i32()` →
  `get_u32_exact()`. Trigger: constants-count VLQ just above `i32::MAX` (`80 80 80 80 08`).
- **#21 sunsignedbigint-type** — remove the version gate on type code 9 in
  sigma_type.rs. Trigger: has_size pre-v3 tree with type code 9.
- **#23 zero-output/token** — remove `check_has_outputs`/`check_positive_assets` in
  structural.rs. Trigger: tx with empty outputs or a 0-amount output token.
- **#25 non-sigmaprop-root** — remove `check_sigma_prop_root(...)` in ergo_box.rs.
  Trigger: sizeless header `0x00` + opcode `0x0A` (Const(SBoolean)).

The `bytesWithNoRef`/cost/mining bugs (#2, #3, #10, #11, #15, #16, #22) and
soft-fork spend semantics (#24) are **SD** — gated by the replay driver, not the
wire generators.
