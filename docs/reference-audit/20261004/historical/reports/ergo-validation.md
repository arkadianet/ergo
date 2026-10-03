# ergo-validation audit — 5d62fd58

**Readiness: NOT_READY.** Authored coverage is complete. Eight source-confirmed findings comprise six P2 and two P3 findings; no P0/P1 or demonstrated consensus split is claimed. Public parameter codec laws, raw resolved-box identity, global rejection ordering, cumulative script settings and test assertions need correction. Forward data-input visibility and testnet launch compatibility require separate external validation.

## Scope and baseline

Review-only on 2026-10-03, HEAD `5d62fd5851e74fcb965b4aba50e1b423127f46f1`, branch main, crate 0.10.0/edition2021. Rust/Cargo1.95.0, native Linux x86_64, kernel7.1.5/glibc2.39. Session baseline preserves the preexisting README modification and untracked audit/prompt documentation. Only ignored session artifacts were written. No source, tests, fixtures, expectations or adjacent repositories changed. No new custom demonstrations, injection, live database, wallet, external node or campaign was used.

All 96 authored crate files were fully read: 30,739 lines and 1,202,871 bytes, including every Rustdoc/comment/test/helper, manifest, seven diagnostic targets and all registered integration fragments. Prompt and codemap are two additional primary files. COMMON, assignment, contribution/security/architecture/compatibility/configuration documents were read; unchanged previously completed shared-document reads are identified in the ledger. All hashes revalidated. Source includes and fixtures are recorded with 351 exact-hash shared integrity/provenance receipts; the broad shared inventory is not a claim that all 351 were replayed by this crate. Primary workspace ownership closes generator/provisioning reads; consumers and assertions here are independently read. Build output/private runtime data and full transitive dependency source are excluded, with selected boundary reads expressly scoped.

Evidence files: `ergo-validation-coverage.json`, `ergo-validation-evidence/results.json`, full command logs, `shared-fixture-coverage.json`, `external-source-receipts.json`, and root shared receipts. Pinned Ergo Scala v6.0.5 is `5528ef569a41ebccbc8658212e6ee3c97d990b96`; fixture-specific 6.0.2/6.0.3/6.0.5 and sigma6.0.6 authorities remain distinct. Root `shared-evidence/root-reference-hashes.json` confirms selected Scala state and Sigma arithmetic identities. Historical campaign result files prove captured bytes/results, not fresh HEAD executions.

Features: no default feature; `test-helpers` enables trusted constructors/helpers, `cost-trace` enables Sigma tracing, `diagnostics` includes tracing and gated diagnostics. Dev self-dependency enables helpers/tracing during tests. Isolated normal/build production tree contains no ergo-state dev cycle, proptest or validation test-helper/diagnostic activation. Crypto/AVL dependencies contain runtime RNG through sigma/AVL; it is a dependency behavior, not leakage of this crate's dev feature. No authored unsafe/FFI/manual Send/Sync was found. Dependency unsafe/platform proofs belong to their owners; no Miri/native other-platform or 32-bit result is claimed.

## Checked-object trust map

| Artifact/entry | Proves | Caller/cooperating obligation |
| --- | --- | --- |
| PowCheckedHeader::verify_pow (`header/mod.rs:332`) | Autolykos solution predicate | Supplied header ID is trusted; parse-time group points, source bytes, parent, clock and difficulty are not derived here |
| validate_header_after_pow (`header/mod.rs:377`) | Parent ID, timestamp monotonicity, votes213/214, nBits/height via crypto difficulty | Caller establishes bytes/ID, group sideband, ingress future time; block caller gates212/215 |
| CheckedHeader::from_persisted_parts (`header/mod.rs:84`) | Exact byte hash, EOF, pow_validity=1, metadata height/parent/time agreement | Metadata PoW flag and persistence origin are trusted; no new PoW/difficulty/group check or canonical rewrite |
| CheckedHeader trusted helpers | No proof | Feature-gated, excluded from minimal production graph; test fixtures legitimately use them |
| CheckedTransaction | Derived bytes-to-sign ID, structural/monetary/height/re-emission and selected script/cost checks | Raw route trusts UtxoView identity (EV001); parsed route checks identities; sideband and checkpoint are explicit trust boundaries |
| CheckedBlock | Section linkage/roots, extension/interlinks/window/size and checked txs in original order | Does not itself authenticate/update UTXO, check final AVL root, choose branch, commit, or establish durability; STATE/SYNC own those |
| NipopowVerifier | Configured structural/Merkle/connection/difficulty-context/per-header-PoW predicates and strict best-proof selection | Optional genesis is explicit trust choice; syncing caller must bind network, m/k/quorum and checkpoint. Same-stack prove/verify is not independent soundness |

Private fields do not make these objects proofs of every node obligation. Public persisted constructors trust stored metadata, public parsed validators accept script skipping and point sidebands, and feature helpers can create unchecked objects.

## Transaction entry-point comparison

| Path | Bytes/canonicality | Resolved identities | Group checks / scripts / context |
| --- | --- | --- | --- |
| Raw `validate_transaction` (`tx/mod.rs:122`) | LocalPolicy size, version-aware decode+EOF, structural then exact reserialization | Presence/order by lookup; returned box identity not checked | Collected complete wire points checked early; scripts run, supplied params/rules/header context |
| Parsed (`:224`) | Reparse original bytes to collect points, then parsed tx canonical equality | Length + computed ID for input and data vectors | Reparse uses default reader context by deliberate Scala compatibility; `skip_scripts` public trust |
| Parsed+GE (`:270`) | Canonical equality, structural | Same defensive identity checks | Supplied points must be exact aligned parse sideband; empty/incomplete points are caller violation, not type-enforced completeness |
| Sequential block (`block/validate.rs`) | Section commitments before expensive structural/size work, per-tx canonical bytes | Overlay input vs data semantics, parsed identity check | Nine tip-first evaluator headers; target params; trusted script checkpoint retains structural/monetary/EIP27 checks |
| Parallel block (`:541`) | Same commitments, layer-wide serial resolution then Rayon validation | Overlay changes between successful layers | Points indexed by tx with reparsing fallback; layer speculation and error order differ (EV003/Q018) |
| Mempool / mining | Cooperating caller derives upcoming candidate snapshot, local policy and admission | Caller selects authenticated/current UTXO and consistent overlay | Ten upcoming-context headers, rules/params/version/re-emission/checkpoint coherence belong to owners; standalone public API is not admission policy |

Per-output positive assets precede height and monetary checks. ERG and token accumulation use the intended bounds/overflow checks; mint identity is first input, burning is allowed, duplicate references and counts are separately constrained. Rule124 applies at block version≥3. EvalBox retains raw script/register bytes, typed values, tx ID/index, tokens and creation height; SELF/context version quirks are deliberately preserved. Init token-access counting, script costs, per-input crypto rounding, failed reduction/proof costs and rent fallback are covered by independent fixture families, not inferred solely from round trips. JIT overflow stays distinct from ordinary cost-limit/script error; ordinary evaluator limit is still enveloped as ScriptError as documented.

## Rule and epoch matrices

| Rule/contract family | Enforcement and reference coverage | Limits |
| --- | --- | --- |
| Header PoW, nBits/height, parent, timestamp | Header+crypto split, real early headers, persisted metadata rejection tests | Future time at actual ingress; canonical reset testnet/activation header ranges partly ignored |
| Votes212–215 | 213/214 at header, cumulative disabled212/215 at block caller, epoch unknown-vote handling | Header-only artifact cannot claim212/215; clock/version/by-height assumptions remain caller-specific |
| Transaction structural101+ / positive108 / output111/112/120/121/124 / sums115–117 / scripts | Independent rejection/tree activation and cost corpora plus unit boundaries | Multiple violations differ between raw/parsed staging; raw identity EV001; not every mainnet tx has resolved UTXO |
| Block section/root/extension400/404–406, interlinks401/402, window407, size306 | Both drivers, negative tests, scrypto batch-Merkle/interlink captures | Final ADProof/state root belongs to STATE/SYNC; rule306 uses parent parameter intentionally while target tx prices use validated target row |
| Epoch408–415/settings/version/subblock rules | Parsed proposed update, recompute and cumulative matcher, independent epoch-extension/tally corpus | Testnet authority Q002 and cumulative script map EV006; missing archival ancestor cannot be called invalid consensus input |
| EIP27 | Shared reemission core, NFT/token branches, ERG payment/output proposition, wallet helper seam | Caller must supply network rule inputs; test default None is not public-mainnet proof |
| Storage rent | Eligibility, short-index fallback, output/value/script/register/token shape, wrapping i32 fee and acceptance short circuit, pinned JVM cases | Q013 positive-again wrap needs an actual valid full box/rate/context oracle, not large-size arithmetic unit example |
| Cost/block cap | Independent verify/stateful costs, whole block synthetic proof fixtures, sweeps/exact cap/plus one/stop-order | Existing static cap cannot certify every future voted cap. Scala6.0.6 multiplyExact/addExact match checked JIT overflow; no unique Rust overflow divergence claimed |
| NiPoPoW | m/k generation, levels, connections, recalculation, suffix/prefix, strict comparison/reset/counters, independent Scala binary and scrypto shapes | k/m public literal invariants not supplied by serde alone; genesis None a deliberate choice; sound full bootstrap needs caller network/quorum witness |

| Epoch state | Numeric parameters | Rule settings |
| --- | --- | --- |
| Launch mainnet | v1, default prices | Empty launch; real history establishes changes |
| Launch testnet | Rust v1/mainnet row | Claims same as Scala, contradicted by pinned tag (EV005/Q002) |
| Launch devnet | blockv4 (Interpreter60), default prices | Explicit devnet60 empty update; not claim for devnet50 |
| Ordinary epoch | Signed votes, min/max/step/rounding and fork state carried, recompute persisted at epoch start | proposed update distinct from newly activated delta; matcher compares cumulative prev.updated(delta) |
| Fork proposal/tally/reject/approve/activate | Threshold/window, old pre-activation chain state and hardcoded v2 transition then v4 subblocks | cumulative settings fold at STATE; script conversion drops earlier epochs (EV006) |
| Target first block / ordinary continuation | for_block selects validated target row, otherwise parent row | Core cumulative gates use store settings; script map only selected row delta |
| Persist/reopen/Mode2 first trusted epoch | v1 legacy vs v2 update blobs, exact persistent EOF, reconcile/migration STATE-owned | Mode2 claim may seed cumulative into one row once; this does not establish later script-map continuity |

Votes i8::MIN, signs/opposites/duplicates, threshold ties and missing approved IDs have distinct errors/legacy JVM exceptions; no widening of intentional Scala wrapping arithmetic is recommended. Consensus extension settings decode is deliberately lenient about trailing/update fallback, while persistent decoding is exact. Public write laws require stronger invariants (EV002).

## Findings

### EV001 — P2 — Raw validation omits returned box-ID verification

Category API correctness; **SOURCE_CONFIRMED**, conditional library trigger. Raw `tx/mod.rs:161–162,381–406` accepts whatever `UtxoView::get_box` returns for each requested ID. Parsed routes call `verify_resolved_inputs_match`/data equivalent (`:280–281,408–457`). A mistaken view can therefore feed different SELF/value/tokens or mint context through the raw route and construct a CheckedTransaction if other conditions pass. Authentication of a legitimate UTXO view is caller-owned; no compromised canonical node DB or network ingress is proved. Expected contract is the advertised checked artifact and parity with parsed defensive checks. Source proves the missing guard, not a mainnet acceptance divergence.

Fix: apply the same ID checks after raw resolution, with explicit typed error and order decision; document trust of authenticated bytes separately. Regression: ordinary view returns a well-formed different-ID box of conserved value, then raw and parsed reject input and data mismatch; verify cost before/after matches intended ordering. Existing cost oracle setup knowingly trusts keyed view results and misses this guard. Keep Scala raw/canonical box identity question SER007 separate; a normalization change needs its own reference witness.

### EV002 — P2 — Public active-param writers can emit records their readers reject

Category codec/API law; **SOURCE_CONFIRMED**, caller-built params. `active_params/persist_codec.rs:18–42` validates only extra-ID collisions/duplicates. `serialize(:64–105)` accepts negative named cost fields that `deserialize(:188+)` rejects, and narrows unique entry count to u8 (`:87`): 256 allowed unique IDs wrap to zero. `context.rs:81–146` has debug-only nonnegative guards and release widening casts. `extension_codec` additionally permits extra124 through the persist invariant while emitting the separate proposed-update124 field, causing duplicate extension keys. Parsed/recomputed canonical rows constrain numbers and current extras; canonical bad-row ingress was not proved.

Expected serialize→deserialize law and the documented invariant that a successful stored row is readable are violated by public values. Fix validate every persistent numeric/count invariant with checked narrowing, reserve extension-specific124 when emitting extension, and use validated conversion or fallible caller-built params. Preserve low-byte blockVersion behavior and consensus lenient update decoding. Regression covers each negative field, 255/256 count, and extra124 round-trip; no resource-heavy run needed. Existing tests cover reserved/duplicate extra and read negatives, but not every accepted writer value.

### EV003 — P2 — Parallel “first failing tx” claim holds only inside a layer

Category deterministic errors/testing; **SOURCE_CONFIRMED**. `block/layering.rs:112–128` schedules earlier producers as dependencies and `block/validate.rs:565–611,664–679` resolves/returns layer errors before later layers. A higher-index independent tx in layer0 can fail before a lower-index dependent tx in layer1. Within one layer, a later serial missing-input failure also precedes an earlier dispatched script failure. Comments claim sequential original-index first error (`:670`). Acceptance/cost on successful blocks is a separate output; no consensus divergence follows from this ordering proof.

Fix choose/document global original-order rejection semantics and implement an ordering-preserving plan or a narrowed contract with validated compatibility decision. Regression uses existing small bounded DAG helpers: independently failing lower dependent and higher independent transactions, plus earlier script failure/later missing input. Assert exact index, rule and partial cost for sequential/parallel against pinned reference when claiming parity. Stop-after-invalid fixture covers a particular order, not all cross-layer shapes.

### EV004 — P2 — Vector integrity test counts unparsable bytes as passing

Category test assurance; **SOURCE_CONFIRMED**. `tests/it/vector_integrity.rs:93–113` increments parse_fail yet file_pass, and hex failure explicitly continues as pass; final assertion only checks ID-versus-bytesToSign mismatches (`:133–151`). Parser uses a temporary reader without EOF assertion. The stated “every transaction bytes well-formed” contract can pass despite broken bytes or trailing junk. Baseline PASS does not repair the blind spot.

Fix separate hash consistency from semantic decode counts, fail nonzero parse failures, assert full consumption and nonempty intended denominator, classify intentionally degraded/versioned vectors explicitly rather than accepting every failure. Regression uses an ordinary deliberately invalid small vector through helper logic and asserts failure; exact existing fixture expectations remain unchanged pending authority.

### EV005 — P2 — Launch “Scala identical” claim and test oracle contradict pinned source

Category compatibility documentation/test authority; **SOURCE_CONFIRMED** as false authority, runtime consequence unresolved Q002. `active_params/launch.rs:30–46,85–98` calls testnet/mainnet byte-identical and tests equality. Pinned Scala v6.0.5 `settings/LaunchParameters.scala:15–17` gives testnet Interpreter60 blockv4 and proposed disable215/409. This is not settled by a Rust self-equality test or a historical different reset. Source receipt pins exact bytes/tag. Current/reset network genesis, first headers and first epoch h1024 acceptance were unavailable, so this finding does **not** assert that changing Rust launch to v4 is immediately correct or demonstrate split.

Fix correct authority/document the chain generation, then derive launch from an independently captured network fixture; retain explicit historical-chain support if required. Acceptance must include exact genesis/first header/voted row+h1024 extension for the chosen supported testnet and pinned Scala. Existing assertion would reject the pinned-source row while advertising it as parity.

### EV006 — P2 — Script rule settings lose cumulative statuses at subsequent epochs

Category context/activation correctness; **SOURCE_CONFIRMED** map loss, present canonical outcome unresolved Q021. `context.rs:8,119–138` says cumulative but copies only selected row `activated_update.status_updates`. `voting/recompute/mod.rs:134–138` intentionally replaces that field with the new epoch's delta; STATE `active_params.rs:108–135` separately folds all prior deltas. Production UTXO `ergo-sync/src/block_proc/utxo.rs:459–479` and digest `:549–568` pass for_block unchanged to script bridge `tx/script/mod.rs:256`. Thus an unchanged epoch can erase an earlier script status even though core disabled-rule gates correctly use cumulative store settings. Newly activated target statuses must also apply to the target first block.

Consequence requires a reachable failing Sigma rule for which the retained status changes `is_soft_fork`. A6 replacements1007/1008/1011 are deliberately ineffective at activation3 (`ergo-sigma/src/evaluator/types.rs:221–239`), so this map loss alone proves neither current chain rejection nor split. Changed/other replacements and supported future transitions retain conditional significance. Outer reader ID1007/1008 versus embedded remapped1017/1018 remains distinct Q011; do not fix it by globally renaming.

Fix obtain cumulative target settings (`prev.updated(target_delta)`) and map that to Sigma once at caller context boundary; make delta vs cumulative types unambiguous. Regression: retained supported status across two ordinary epochs and reopen, exact target activation block and before/after; assert context map plus an independently witnessed applicable parse/reduction verdict/cost. Existing oracle harness seeds active.activated_update with cumulative captured extension settings, bypassing the production loss.

### EV007 — P3 — Strict public Rustdoc fails in 25 locations

Category documentation build; **REPRODUCED** with exit101 in strict-docs.log. 23 links expose private items and two unresolved links (`popow/algos/interlinks.rs:98`, `popow/verifier.rs:95`); module links span active_params/block/header/popow/voting plus TxValidationCtx and private extension max. Public docs therefore fail the required warning-denying command. Fix links to exported contracts or render private implementation names as code, and resolve cross-crate dependency text without introducing the dev cycle. Acceptance: same strict command exit0 under all features; do not suppress diagnostics wholesale.

### EV008 — P3 — Public checked/proof prose overstates implementation

Category contract clarity; **SOURCE_CONFIRMED**. `header/mod.rs:56–57,68–76` calls caller-provided/raw hashed IDs canonical computed internally; `:408–409` claims the only checked constructor despite public persisted path. `tx/mod.rs:74–82` says all checks/unforgeable without mentioning public skip_scripts/sideband trust. `popow/proof.rs:1–2,110–116` promises ≥, both-invalid true and panic-catching/logging, while implementation strict comparison/both-invalid false/no catch disagrees and tests enforce false. Overlay prose (`block/overlay.rs:66–74`) characterizes Scala lookup as sequential although pinned state builds all outputs (Q018).

Fix contracts to enumerate proven facts and caller trust, preserve actual strict tie behavior until independent comparator authority settles change, and remove contradicted sequential claim. Focused doctest/example or doc assertion should show raw hash, trusted rehydration, checkpoint and strict tie. No additional generic API abstraction is required.

## Explicit unresolved compatibility questions and evidence gaps

- **Q018 future DATA visibility:** Rust UTXO base is StateStore (`utxo.rs:462–479`); sequential/parallel overlay only sees published earlier transactions/layers and layering ignores future producer edges. DigestUtxoView already inserts every block output (`ergo-state/src/digest_utxo_view.rs:71–89`). Pinned Scala UtxoState77–84 and DigestState45–59 resolve ALL outputs before original-order transaction execution. Parent-state data lookup may legitimately return None before inserts (STATE dry-run/proof contract); future *spending* still generates REMOVE+INSERT and may fail state application. Do not use that spending failure to close future DATA. Source supports a possible Rust UTXO underacceptance or mode discrepancy, and layer scheduling can reveal some future outputs. No actual captured forward-data full block, fresh whole-block Scala/Rust execution or live chain occurrence is demonstrated. Required closure is a valid ordinary full block with all identities, scripts, proof/net operations and final roots, with per-mode/driver verdict/cost—not a generic DAG test alone.
- **Q011 outer governance:** embedded deserialize remaps1007/1008/1011 at activation3 (`ast_walk.rs:326–331`), outer reader identities differ. Disabled alone is not Sigma softfork; replacements at A6 excluded; governance status/parse boundary must be witnessed before claiming rule-ID divergence. SIGMA/SER owners and EV006 are cooperating seams.
- **Q002** testnet authority remains as EV005; source contradiction is confirmed, current chain behavior absent.
- **Q003** static cap/static cost margin cannot certify future voted caps. Checked×10/add arithmetic agrees with pinned Scala6.0.6 java multiplyExact/addExact. No unique Rust future acceptance bug is claimed.
- **Q013** wrapped rent arithmetic deliberately matches reference; >i32max becoming positive again needs valid box-size/rate/value/age/output context and full reference verdict. Large-size unit arithmetic alone is not that witness.
- **SER007/008** raw retained ErgoBox bytes vs canonical ID, register coherence and tx-output→box semantics need their own exact parsing/identity authority; root pinned Scala6.0.6 receipt resolves standalone cached raw IDs differently from Rust canonical IDs, without proving chain occurrence.
- Full archival/L4 epoch campaign replay, current external negative corpus regeneration, authentic network reset/bootstrap installation, native Windows/macOS/32-bit, sanitizers/fuzz/model-checking, representative performance, process-kill/physical-powerfail were not run. This crate owns no durable commit; storage failures/readiness belong to STATE/SYNC/NODE.

## Verification accounting

| Command / feature | Result / exact executed count | Receipt |
| --- | --- | --- |
| cargo test --locked -p ergo-validation | PASS 502; 14 ignored; zero failures (369 lib,132 integration,1 standalone) | baseline.log,8.42s |
| cargo test --locked --no-run -p ergo-validation --features diagnostics | COMPILE_ONLY all registered targets | diagnostics-compile.log,12.74s |
| cargo check --locked -p ergo-validation --lib --no-default-features | COMPILE_ONLY PASS | minimal.log,1.63s |
| cargo check --locked -p ergo-validation --lib --features cost-trace | COMPILE_ONLY PASS | cost-trace.log,1.00s |
| cargo check --locked -p ergo-validation --lib --features test-helpers | COMPILE_ONLY PASS | helpers.log,0.46s |
| RUSTDOCFLAGS=-D warnings cargo doc --locked -p ergo-validation --no-deps --all-features | FAIL exit101,25 diagnostics | strict-docs.log,0.56s |
| cargo test --locked -p ergo-validation --doc | PASS 0 examples | doctests.log,0.18s |
| cargo tree --locked -p ergo-validation -e normal,build,features --no-default-features | PASS production graph, excludes helper dev cycle | production-tree.log,0.09s |
| Shared workspace fmt/Clippy/test/dependency/cost ledger gates | REUSED unchanged pass,7,629 tests/98skips; workspace strict docs failed | shared-evidence/results.json |

All commands use CARGO_BUILD_JOBS=6, locked dependency graph and preserved existing target. Seven standalone diagnostics are inventoried; most bodies require diagnostics and were compile-only, trace_emission remains explicitly ignored. Fourteen ignored baseline cases include missing gitignored activation/header/tx corpora and manual diagnostics; no --ignored was used. Any tests internally skipping absent optional L4 inputs count only their executed assertions, not replay; baseline log/source exposes that early return. The committed L4/history manifests are verified structure/hash evidence; frozen prior Rust binary/results do not establish current full archive parity.

Executed independent fixture families include Scala/scrypto NiPoPoW binary/shape/interlinks, tree-version activation and rejection, transaction-init/crypto/rent verification costs, version/validation-settings sweeps, synthetic full blocks with ADProof roots/price/stop/exact cap, context header windows, early/curated mainnet block/header positives and extension epoch/tally data. Mainnet EmptyUtxo corpus cases measure stateless/expected missing inputs, not full stateful acceptance. Whole block fixture oracle uses Ergo6.0.5/sigma6.0.6 and synthetic authenticated state; it does not certify every historical mainnet state/digest path. All authored helpers/assertions and historical manifests were reviewed; semantics/provenance/hashes remain explicit in shared ledger.

## Remediation and acceptance order

1. Settle ID/canonical-byte ownership with SER and add raw mismatch guard; strengthen persistent writer invariants without changing consensus leniency. Check all STATE writers/readers and release conversions.
2. Thread cumulative target Sigma settings through UTXO/digest/mempool/mining, then validate retained status across epoch/rollback/reopen using independent applicable statuses. Keep Q011/Q021 outcomes conditional until oracle context agrees.
3. Establish global error/partial-cost contract and future-data visibility with independent whole-block evidence; update both drivers and proof/net state application together if required. Avoid inferred forward-spend overacceptance claims.
4. Bind supported testnet chain launch to exact current/historical captures, repair integrity assertions and strengthen multi-layer/context denominators. Preserve independent oracle expected bytes.
5. Correct public trust/tie comments and strict links, rerun relevant scoped commands only after actual remediation. Execute named external campaigns only with validated prerequisites; never treat compilation/history files as passes.

The crate has substantial real independent tests and a mostly clear validation/state boundary. The confirmed contract/test defects and unresolved mode/activation authority prevent reference-node readiness. Coverage is complete, evidence limits are recorded, and these local reports do not certify full-node consensus, operating-system durability or wallet safety.
