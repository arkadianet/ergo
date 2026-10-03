# ergo-ser audit

**Readiness: NOT_READY within the reviewed serializer/API-construction scope.** All 64 authored crate files, all 29,548 lines, were read in full, including inline tests, Rustdoc and manifest comments. Twelve findings are confirmed: eight P2 and four P3. No P0/P1 consequence, consensus split, RSS exhaustion or fund compromise is demonstrated. The findings include reproduced hash-key disagreement, constructor/cached-field coherence failures and writer acceptance defects. Two reader/reference questions remain hypotheses, explicitly excluded from the confirmed count. Root's later ordinary pinned whole-box comparison refines ES-007 and adds ES-012; its distinct evidence and limits are linked below.

This report and its evidence are local artifacts beneath ignored `audit/`. It is an independent crate review; complete node, compiler, validation, REST-JSON, indexer and differential-harness audits retain ownership of their whole implementations. Shared authored docs/generators are coordinated through the workspace audit. Passing captures establish their particular observable contracts, not universal Scala compatibility.

## Scope, baseline and authorities

- Session `20261003T085740Z-5d62fd58`, reviewed revision `5d62fd5851e74fcb965b4aba50e1b423127f46f1`, branch `main`, package 0.10.0, edition2021, `publish=false`.
- Linux x86_64, Rust/Cargo1.95.0, LLVM22.1.2. Cargo commands use `--locked`, `CARGO_BUILD_JOBS=6` and the existing cache/target wrapper. Actual scoped test binaries were under `/home/arkadias/.cache/rust/build/c0/d13e94f11196ff/`. No clean, dependency upgrade, global configuration change or source edit occurred.
- Preexisting modified `README.md` and untracked `docs/audit-2026-10-03.md`, `docs/audit-prompts/`, `docs/audit-remediation-todo.md` were preserved. No applicable ancestor `AGENTS.md` was found. The assignment, COMMON, crate prompt, CONTRIBUTING, compatibility, SECURITY, manifests/toolchain and crate codemap were read fully.
- Crate features: no default feature; `diagnostics` only enables the triage integration fragment. Its complete body was read and compiled; its historical print-only campaign was not run. All other default bodies executed in the package suite. Minimal/default feature compilation does not test a different codec implementation.
- Runtime dependencies are ergo-primitives, bs58 0.5.1, indexmap 2.14.0, num-bigint 0.4.6 and thiserror 2.0.18, with the exact transitive graph in [runtime-tree.log](ergo-ser-evidence/runtime-tree.log). Proptest and serde_json are dev dependencies. No authored `unsafe`, FFI, build script, binary, example or bench surface is present in this crate. Registry-dependency unsafe review and platform closure belong to the shared workspace audit; compilation alone does not prove those contracts.
- Pinned sigma-state primary sources: v6.0.2 commit `23dd29f612249c169d09fae9bca76d7cc02e144c`, v6.0.6 commit `ab0b15ceb9d34f2ccd6e68e3e2a8aa27cd16a042`. The tree serializer, constant store and placeholder serializer are byte-identical between those tags. Full snapshots and SHA-256 values are in [reference/provenance.json](ergo-ser-evidence/reference/provenance.json). TypeSerializer, VersionContext, GetVarSerializer and ContextExtension were also read fully at v6.0.6. ErgoTree's cached-byte/template portion was selected, not its entire implementation.
- Scala index hash ownership was checked against Ergo v6.0.5 commit `5528ef569a41ebccbc8658212e6ee3c97d990b96`: complete IndexedErgoAddress/IndexedContractTemplate snapshots are retained. The address key hashes `tree.bytes`; the template key hashes `tree.template` under versions3,3 and falls back to `tree.bytes` on exception.
- Current ordinary JVM probes use Scala2.12.20, sigma-state6.0.6, scala-cli1.12.1 and Java17.0.17 Corretto from `/home/arkadias/.local/kdex-toolchain/bin`, per-command PATH and `COURSIER_CACHE=/home/arkadias/.cache/ergo-test-tmp/coursier`. A tool hint suggested6.0.7; it was ignored to preserve the pin. No live node, remote submission, new malformed payload, operational exhaustion test or production data mutation was used.

The [machine coverage ledger](ergo-ser-coverage.json) records every owned authored file's current hash, exact full range, contracts, feature status, evidence, findings and remaining test questions. The [readable ledger](ergo-ser-coverage.md) is its companion. External full reads, selected caller/reference portions and generated-data checks have different statuses. [fixture-inventory.json](ergo-ser-evidence/fixture-inventory.json) hashes and structurally validates105 linked fixture/provenance files totaling7,533,422bytes. These data checks are not claimed as full authored-prose reads or fresh oracle execution. The two binary NiPoPoW inputs have additional current semantic test assertions, exact hashes and command links in [binary-semantic-checks.json](ergo-ser-evidence/binary-semantic-checks.json).

## Contract and ownership map

The layer owns wire verdicts, consumed position, accepted normalization, typed carriers, serializer gates and sufficient raw/canonical separation for its consumers. Crypto/proof verification, script execution, state rules, voted limits and remote admission are owned downstream. SEC1 prefix/identity handling is a serializer contract; a general compressed point's curve validity requires the relevant later validation. Some nested header routes already harden their serializer failures. Neither a successful parse nor an `ErgoTree` alone proves interpreter support, active-network validity or canonical original bytes.

| Surface | Entry/state contract | Later owner or intentional difference |
| --- | --- | --- |
| Headers/PoW/difficulty | Header version chooses v1/v2 solution layout; raw header body/unparsed span retained; ID and no-PoW preimage are separate from parsed serialization | Header/state/PoW validation; accepted nonminimal/identity forms may normalize |
| Block transactions | Wire version and activated version have separate scopes; fresh transaction binding stores; token table first-occurrence order; tx slices/group/header sidebands aligned | Block validation supplies activation and checks rules/count/size/state |
| Transactions/inputs | Signed, unsigned and signing writers share output/token order; signing omits proof bytes while canonical extension stays committed | Wallet/interpreter/signature validation; parsed-only type support is not execution support |
| Boxes | Standalone and token-indexed boundaries differ; structural tree end precedes height/tokens/registers; full box adds tx ID/index | Wire-cap token count differs from policy cap; density/canonical register node forms matter |
| Typed values/registers/extensions | Type descriptor and data are distinct; evaluated Constant/CreateTuple/ConcreteCollection/GroupGenerator identity is retained where Scala does | Rule1019/header/option gates and signed extension IDs/count; map duplicates normalize as reference maps |
| ErgoTree | Header, shared reader level, version, constant store, value bindings, unresolved-method checkpoint and position budget form a state machine | Plain-tree API is intentionally lenient; box-script gates supply context; degraded failures preserve reference failure state |
| Opcode/type inference | Every registered payload parsed/written/walked; known receiver/result/operand types decide gates; unknown inferred types remain indeterminate | Interpreter/compiler own execution/compilation; registry parity is not complete typing proof |
| Addresses | Base58/checksum/network/type routing, P2PK/P2S/P2SH content and preimages | Public raw encoders may accept unchecked bytes; callers must choose validation and network policy |
| Extension/AD/section IDs | Ordered fields and fixed wire lengths; AD bytes opaque; section IDs use reference prefix/preimage | Stateful extension/AD/root verification downstream |
| PoPoW/NiPoPoW/batch proof | Fixed-width vs VLQ lengths, caps, EOF, empty sibling marker, side normalization and field order | Validation converts/reduces proofs and checks linkage/interlinks; codec parse does not prove chain quality |

### Version and entry-point matrix

The table describes supported branches and ownership; it does not claim a Cartesian product was independently captured.

| Axis | Plain tree | Box/transaction/nested value | Compiler/trusted entry |
| --- | --- | --- | --- |
| Header v0, sizeless | Structural root end; constants if segregated; no implicit EOF | Legal v0 script, gated root/methods; following fields start at actual root end | Writer/new tree must have writable shape |
| Header v1–3, sized | Declared size read through `getUInt().toInt`; successful parse uses actual body consumption | Same parse plus box acceptance gates | Header/reserved bits retained; normalization may alter size/VLQ/body |
| Header nonzero, sizeless | Lenient reader may return a structure | CheckHeaderSizeBit/rule1012 rejects; nested failure hard/soft class depends on its stage | Not made valid by a construction/cache assertion |
| Header v4–7, sized | Reader can return opaque Unparsed bytes | Activation<2 leaves version require inert; activation>=2 rejects header above activated version | Trusted stored-data read skips revalidation gates, still structurally parses |
| Activated0/1 vs2/3 | Scope from `VlqReader`, default1; plain reader is not complete network acceptance | Caller must supply actual block/context version; v3 at activated2 rejects at box gate | Compiler embeddable override is a distinct escape hatch (ES-010) |
| Segregation off/on | Inline constants vs table/placeholders; top body temporarily uses its own pool bound | Same reader/depth reused through nested values; sizeless inner pool scope remains EP-R1 | Segregating writer append order, Relation2 equality optimization and re-read shape tested |
| Reserved bits0xE0 | Preserved in parsed header/opaque original | Not used to select layout or activation | Masked on reconstruction, not silently cleared |
| Root known SigmaProp / known other / unknown | Determinable root gate; unknown inference cannot justify rejection | Known non-SigmaProp wraps under size or rejects sizeless; method resolution participates | Opaque root is carried, not evaluated as a trivial replacement |
| Registry v5/v6 | Header governs registry and explicit type-argument width; activation governs some rule metadata | Sizeless inner headerv0 uses v5 registry even inside outerv3 | Generated method signatures pin6.0.6; older resolution fixture pins6.0.2 |
| Trusted false/true | Trust propagates to body sub-readers | False: tree/root/header/threshold/etc acceptance; true: justified already-accepted persisted boundary only | Full provenance of every trusted caller remains downstream-owner work |

On sized success, the limit is the reader's begin-read position limit anchored at tree start+4096, not the declared-size region. On wrap, the reader rewinds/advances to `tree_start + header_and_size_width + declared_size`; signed/wrapped sizes can place it before body start. Certain hard serializer errors escape wrap; validation-class failures degrade. Group-element/header sidebands are truncated to the actual failed checkpoint as the reference requires. Failed reader frames intentionally retain level/binding state in some cases; resetting every field on every error would change compatibility. Transactions begin fresh binding scopes, while same-reader nested trees have distinct constant/version/checkpoint ownership.

### Raw, canonical and identity ownership

| Object/observable | Authoritative bytes | Current risk |
| --- | --- | --- |
| Header ID / PoW preimage | Retained header input/no-PoW span where required; canonical writer is separate | Captures cover selected accepted normalization, not every header quotient class |
| `ErgoBoxCandidate::ergo_tree_bytes` / script propositionBytes | Original received tree span, including accepted noncanonical forms | Correct ordinary-reader distinction; caller docs still conflate canonical and accepted |
| Candidate serialization, tx output/signing, newly constructed box ID | Canonical serializer output, with opaque tree exception; evaluated node identity retained | ES-007 constructor omits canonical cache; ES-008 mutable parsed registers can disagree with cache |
| Parsed standalone box ID | Scala caches the entire consumed wire span and hashes it; canonical reserialization is a separate observable | ES-012 ordinary reader loses that box-level identity cache |
| SpendingProof | Opaque proof bytes plus canonical extension; checked raw ctor normalizes | Existing noncanonical-extension regression distinguishes raw parse from signable write |
| Transaction IDs/bytes-to-sign | Canonical output/token table/extension order; proofs removed for signing | Broad captures passed; uncaptured adversarial/order combinations remain unproved |
| Group-element sideband | Parsed/canonical encoding, including all-zero normalized identity | Primitive EP-004 documents raw-vs-normalized comment error; original input span is separate |
| Header sideband / tx slices | Parsed true spans, per-transaction aligned collection | Cross-degrade/nested/reused-reader cases have regression coverage, not universal framing proof |
| Index address tree hash | Scala cached `tree.bytes`; Rust stored index also hashes received tree bytes | ES-006 API helper hashes reconstructed bytes and can select another key |
| Template hash | Scala raw extracted template from cached tree bytes; cached tree fallback on extraction error | ES-006 AST serialization/opaque refusal loses this distinction |

## Confirmed findings

### ES-006 — Tree and template helpers use the wrong byte ownership

**Category:** reference/API/index correctness; **severity:** P2; **evidence:** REPRODUCED. Owner: ergo-ser hash helpers; coordinated API/indexer integration.

**Expected/authority:** [hash.rs:35](/home/arkadias/Coding/remote/ergo/ergo-ser/src/ergo_tree/hash.rs:35) promises IndexedErgoAddress/tree-template parity. Pinned Scala `ErgoTree.bytes` keeps the received bytes, and `template` extracts the header/constants-stripped body from those cached bytes. Ergo v6.0.5 IndexedErgoAddress hashes `tree.bytes`; IndexedContractTemplate hashes `tree.template` with raw cached-tree fallback.

**Actual/proof:** `tree_hash_from_bytes` at line48 parses and writes a fresh AST; `template_bytes` at line104 writes the body; `template_hash_from_bytes` at line133 refuses all wrapped trees. Existing helper-generated benign `1000d17f` is accepted by JVM6.0.6 at activation1/2/3, consumed4, cached bytes `1000d17f`, canonical serialization `1000d10101`, template `d17f`. Rust produces tree hash `e398e8ba4c181618bf2b4d3630ecd5cbde5245f348c0f90f6c6c23d551e8d2eb`; cached input hash is `feaef873b8e36dacb2b2b6a785f2a8cbb52be78ff31af42855895ebf12dd8846`. Rust template hash `d62151f990f191c102a6fe995b89ed3d0f343a96f13789a370821084f3b1f088` differs from raw-body hash `e46fe06925a344c48b63e2eeadbbaaa114079588ba6735b258815e995c0eeed4`. Existing opaque unit fixture `0b01fd` also yields JVM rootLeft but template `fd` at activation1/3; activation2 correctly rejects headerv3. The helper's claim that Scala template always throws on Unparsed is disproved.

**Reach/impact:** Accepted normalizing input on API byErgoTree handlers128–136 reaches the helper without an equality gate, then address-index lookup. Indexer `segment_id.rs` separately hashes raw received tree bytes. Such a query can select the wrong segment; template grouping can disagree with Scala or omit opaque outputs. Current logs establish keys and source path, not a populated production-index incident or consensus ID divergence.

**Fix/acceptance:** Retain/extract the received header/constants/body spans and use the reference cached-byte basis, including opaque extraction/fallback. A parsed-only tree cannot recover discarded original bytes; make its hash API ownership explicit. Preserve parse/trailing-byte policy separately. Add ordinary JVM/Rust hash assertions for these existing normalization/opaque fixtures and an API lookup against a segment inserted under the stored raw key. Indexer template changes need apply/rollback/rebuild and stored-key migration review. Existing golden round trips compare bytes and do not independently assert hash ownership. Evidence: [JVM log](ergo-ser-evidence/pinned-tree-probe-opaque.log), [Rust log](ergo-ser-evidence/rust-benign-probe-corrected.log), pinned reference snapshots.

### ES-007 — Checked raw box construction omits canonical serialization

**Category:** public construction/identity coherence; **severity:** P2; **evidence:** REPRODUCED. Owner: ergo-ser checked constructor; REST-JSON/wallet callers own integration.

**Expected/authority:** Candidate serialization and newly constructed box IDs use canonical serializer output. Ordinary standalone/indexed candidate readers compute `canonical_tree_bytes` and write canonical registers. Checked construction should produce the same serializable candidate. This differs from a parsed whole box's cached-wire ID: pinned Scala `ErgoBox.scala:73,87–92,214–224` retains its entire input, as ES-012 establishes. A repair must preserve both contracts.

**Actual/proof:** [try_from_raw_parts:160](/home/arkadias/Coding/remote/ergo/ergo-ser/src/ergo_box/mod.rs:160) validates parse equality/EOF/gates, then at line219 stores `canonical_tree_bytes: None` and the supplied register bytes. Existing benign whole-box unit fixture with tree `00d17f` passes. The ordinary candidate writes `00d10101`; a newly assembled Rust box then yields ID `8a8952eb1c47a928f5480ae513e26066390022825fefd1f0cb5b39c300063ed0`. Checked construction writes `00d17f` and yields `733c16cac9f5d9187eda2cffcd57830e0173aaf1650e55ba9e4b8f1b43cbd1c3`. Root's later sigma-state6.0.6 comparison at activation1/2/3 confirms the canonical bytes and first ID for a Scala box reconstructed from those parsed fields. Scala's standalone parse retains the raw bytes and second ID instead. Thus constructor serialization remains defective; identical ID for every entry path would be the wrong acceptance criterion.

**Reach/impact:** Safe in-process callers of the checked API with an accepted normalizing form. REST-JSON Preserve has an analogous reviewed seam: decode.rs183–221 feeds mode-returned raw tree/register bytes into the unchecked trusted constructor. Root's selected wallet scan trace uses Preserve then computes/stores ID and serialization. That seam requires owning REST-JSON/wallet evidence; this finding does not infer remote consensus submission or a deployed corrupt wallet record.

**Fix/acceptance:** Keep original tree bytes for proposition access, compute its canonical cache through the shared ordinary-reader policy, and canonicalize register serialization while preserving reference evaluated-node forms. Document trusted constructor's canonicality requirement honestly: prior acceptance alone does not establish it. Compare checked/new/ordinary candidate serializers on existing accepted-normalizing fixtures against Scala's candidate serializer and newly constructed box ID. Separately assert Scala's parsed whole-box cached ID (ES-012), while propositionBytes stays unchanged. Reconcile Preserve mode and exact persisted identity contracts before changing wallet/indexer keys. Current constructor tests use canonical or mismatching inputs, so miss accepted normalization. Evidence: [bounded Rust log](ergo-ser-evidence/rust-benign-probe-corrected.log), [root Scala comparison](shared-evidence/box-reference/results.json).

### ES-012 — Parsed whole-box identity incorrectly follows canonical reserialization

**Category:** standalone codec/reference identity; **severity:** P2; **evidence:** REPRODUCED by root with an existing fixture. This is separate from ES-007's newly constructed candidate serialization.

**Expected/authority:** Pinned sigma-state6.0.6 `ErgoBox.sigmaSerializer.parse` caches exactly the consumed whole-box span; `ErgoBox.bytes` returns that span and `id` hashes it. `sigmaSerializer.toBytes` still writes canonical parsed fields. Public construction without a cached span hashes the canonical serialization. The selected pinned source hash and executed comparison are in [results.json](shared-evidence/box-reference/results.json).

**Actual/proof:** Rust [whole.rs:53](/home/arkadias/Coding/remote/ergo/ergo-ser/src/ergo_box/whole.rs:53) retains parsed candidate fields but no whole-box input cache. [mod.rs:288](/home/arkadias/Coding/remote/ergo/ergo-ser/src/ergo_box/mod.rs:288) and `box_id_with` always hash canonical serialization. Existing SER fixture `c0843d00d17f0100001d823ee9ea823cc80232a19181efad41d66849c33ed5d0d6c5750b8d60f1d66400` is accepted by Scala6.0.6 at activation1/2/3, consumes all42bytes, and has parsed ID `733c16cac9f5d9187eda2cffcd57830e0173aaf1650e55ba9e4b8f1b43cbd1c3`. Canonical serialization is43bytes and reconstructed ID is `8a8952eb1c47a928f5480ae513e26066390022825fefd1f0cb5b39c300063ed0`; Rust ordinary read returns that reconstructed ID. Both Scala observables are independently recorded; a canonical fixed point cannot detect this discrepancy.

**Reach/impact:** Public standalone, accepted-box and vector-assisted read paths share a box type incapable of this distinction. Callers using the resulting box ID can disagree with the reference's parsed object for accepted normalizing input. Actual canonical-chain occurrence, valid transaction/proof consequences, wallet records, consensus divergence and fund effects were not demonstrated. Transaction-output sealing constructs a new box and follows a different reference contract; it must not be changed to hash arbitrary received candidate bytes.

**Fix/acceptance:** Represent and preserve parsed whole-box identity bytes separately from canonical writing/new construction, with mutation semantics that keep identity and fields coherent. Assert parse verdict, full consumed count, cached bytes/ID, canonical bytes and reconstructed ID independently against the pinned reference for this existing fixture, plus ordinary canonical controls. Review held state/digest, nested SBox, wallet, REST and indexer caller contracts before any format/key migration. Current ordinary normalization tests assert canonical output, omitting the distinct parsed whole-box ID.

### ES-008 — Public register mutation leaves box serialization and identity stale

**Category:** public mutable-state/cache coherence; **severity:** P2; **evidence:** REPRODUCED.

**Expected/authority:** A safe candidate's inspected R4–R9 and `register_bytes`/writer/ID must describe the same object. Tree fields already use private accessors to enforce their analogous invariant.

**Actual/proof:** [mod.rs:72](/home/arkadias/Coding/remote/ergo/ergo-ser/src/ergo_box/mod.rs:72) exposes `additional_registers` publicly but keeps `register_bytes` private. Standalone/indexed writers serialize the private cache. An ordinary empty-register candidate mutated with one Boolean register reports parsed count1, still cached `00`, and unchanged `box_id`, as the bounded probe shows. No unchecked call is needed.

**Reach/impact:** Any safe in-process consumer mutating the public field after construction/read; all features. Inspection/evaluation and serialized commitment disagree. Remote invocation/mutation and wallet fund effects are not established. Existing tests construct immutable objects and never mutate this cached field.

**Fix/acceptance:** Make the parsed register field private and provide an accessor plus a fallible canonicalizing update, or remove/recompute the serialization cache using current fields. Preserve evaluated node identity, R4–R9 density and raw proposition semantics. Add a one-register update regression showing inspection, bytes, ID and signing output change together; an invalid update must leave the object coherent. This API adjustment has downstream compile/caller consequences. Evidence: [Rust log](ergo-ser-evidence/rust-benign-probe-corrected.log).

### ES-011 — Context-extension writer permits counts the reference refuses

**Category:** writer/API compatibility; **severity:** P2; **evidence:** REPRODUCED.

**Expected/authority:** Pinned6.0.6 ContextExtension serializer line46 errors when size exceeds `Byte.MaxValue`127. The Rust reader's signed count contract and comments also correctly state this127 maximum.

**Actual/proof:** [write_context_extension:66](/home/arkadias/Coding/remote/ergo/ergo-ser/src/input/context_extension.rs:66) allows up to255. A bounded128-entry extension constructed in the shape already used by the reader's regression test writes successfully (385bytes), then its own reader immediately rejects the signed count−128. JVM source independently refuses that writer count. No new malformed network payload was executed.

**Reach/impact:** Public extension/spending-proof/signing APIs with128–255 entries; default/all features. Callers can receive successful serialization for an extension neither reference writer nor reader accepts, leading to locally produced unusable transaction/signing data. No consensus over-accept is claimed; the reader gate already rejects it.

**Fix/acceptance:** Enforce127 before emitting count, return typed WriteError, correct the255 writer documentation. Test127 round trips and128 returns error; callers must propagate it. Negative-byte IDs are a separate reference asymmetry: Scala can represent signed map keys but its reader rejects negative IDs, so do not infer an additional writer divergence without its exact API contract. Existing count tests exercise read rejection after Rust writes the oversized object, rather than asserting write rejection. Evidence: pinned [ContextExtension snapshot](ergo-ser-evidence/reference/v6.0.6-ContextExtension.scala), [Rust log](ergo-ser-evidence/rust-benign-probe-corrected.log).

### ES-004 — Expression collection writer silently narrows its element count

**Category:** writer integrity/API bounds; **severity:** P2; **evidence:** SOURCE_CONFIRMED.

**Expected/authority:** Successful writing of a public expression must encode its declared collection size consistently; public writer uses a Result and other collection writers guard their wire counts.

**Actual/source proof:** [opcode/write.rs:455](/home/arkadias/Coding/remote/ergo/ergo-ser/src/opcode/write.rs:455) emits `items.len() as u16` then all items for ConcreteCollection; line463 does the same for BoolCollection before emitting all packed bits. Length65536 becomes count0 with remaining payload, yet returns success. No65536-element allocation/wire experiment was performed.

**Reach/impact:** Direct construction of public Expr/Payload ASTs above65535; not producible by decoding that u16 count alone. Other entry constructors may cap sizes, but the public serializer is independently callable. A successful write can alter the represented value and leave suffix bytes consumed as following fields. No remote accepted-input or compiler full-path claim is made.

**Fix/acceptance:** Check count before its emission, including the Boolean-compaction path, with a structured WriteError; preserve valid65535 output. Test both variants at/above limit and ensure writer output policy is documented on error. Review callers before tightening API expectations. Existing small round trips and bounded parsed counts cannot reach a narrowing overflow.

### ES-009 — SigmaBoolean reserves a large input-declared child array before reading children

**Category:** resource amplification; **severity:** P2; **evidence:** SOURCE_CONFIRMED with bounded size measurement. No RSS/OOM/remote DoS demonstration.

**Expected/authority:** COMMON/crate resource contract requires soft initial allocation bounds without altering accepted inputs or reference failure order. Other count-driven vectors in this crate use a soft cap.

**Actual/source proof:** [sigma_boolean.rs:147](/home/arkadias/Coding/remote/ergo/ergo-ser/src/sigma_value/sigma_boolean.rs:147),161 and177 read a u16 child count then call `Vec::with_capacity(count)` for Cand/Cor/Cthreshold before validating payload availability. On this native target `size_of::<SigmaBoolean>()` is136bytes. One max-count reservation requests8,912,760bytes. The depth check permits108 simultaneously outstanding conjecture reservations through `read_constant` (first sigma-node depth2), requesting962,578,080bytes before the child fails. The public raw typed `read_value` starts its sigma node at depth1 and can request109reservations, totaling971,490,840bytes, before the110depth check. Existing108-Cand success/109-Cand failure tests corroborate the raw-value depth boundary; no large-count version was executed. This is a source capacity bound plus `sizeof` arithmetic, not resident-memory measurement. Untouched allocator mappings can remain virtual; rejection frees frames.

**Reach/limits:** SigmaProp constants in registers, context extensions and inline/segregated tree bodies reach this decoder. A position/depth/wire size cap does not constrain the count to available children before reservation. API owner full-read evidence caps script-tree hex at128KiB/64KiB decoded bytes and sources64KiB, with per-IP compute token buckets and loopback exemption, but no parse semaphore/CPU permit; parsing is synchronous in async script handlers. The API owner also reviewed `/api/v1/boxes/decode`: routes/decode.rs201–231 hex-decodes an uncapped tree and service.rs38–49 parses register constants synchronously, with admission classification reviewed separately by the API owner (HeavyRead rather than the script Compute lane). Its actual aggregate routing/body-size dependency bound remains unverified. These are reachable API surfaces, not complete peer admission/concurrency/RSS limits. Node-wide admission and allocator/OS impact remain unproved.

**Fix/acceptance:** Start with a modest soft capacity cap or safe conservative availability bound, grow while reading, preserve valid broad collections and check/read order. Cthreshold shape is checked after children in Scala; moving it ahead can change hard/soft failure precedence. Add bounded allocation-strategy tests and preserve captured depth/conjecture verdict/consumption cases. Existing tests assert arity/depth and tiny-vector behavior, not initial capacity. Evidence: [bounded sizeof log](ergo-ser-evidence/rust-benign-probe-corrected.log); no exhaustion payload retained.

### ES-010 — Compiler embeddable override asserts reference acceptance contradicted by the pinned parser

**Category:** compiler-only parse contract/reference validation; **severity:** P2; **evidence:** REPRODUCED. Compiler owns the compilation/output consequence.

**Expected/authority:** [read.rs:26](/home/arkadias/Coding/remote/ergo/ergo-ser/src/ergo_tree/read.rs:26) says the activation override mirrors Scala table selection and that a headerv0 unsigned type re-parses under activated3. Pinned6.0.6 TypeSerializer chooses rule1017 vs1007 by activation, but its actual embeddable type table uses tree version>=3.

**Actual/proof:** Existing unit fixture `1000d1e6c6a70409` at [tests.rs:1624](/home/arkadias/Coding/remote/ergo/ergo-ser/src/ergo_tree/tests.rs:1624) is accepted by `read_ergo_tree_with_activated_version(...,3)` consuming8bytes. Current pinned JVM tree deserializer rejects that same existing fixture at activation1,2 and3 with `SerializerException: Cannot handle ValidationException, ErgoTree serialized without size bit.` Normal Rust reader, including reader activation3, rejects code9 and matches that rejection direction. The escape hatch changes the type table and is used for compiler self-check, not consensus input parsing.

**Reach/impact:** Public override or compiler self-check for a requested v6 compile emitting headerv0. The helper can approve a tree the reference parser rejects, so its self-check does not establish its stated acceptance guarantee. No fresh full compiler output/replay was executed, and no incoming consensus-parser defect is claimed. The existing regression asserts the erroneous acceptance as expected behavior.

**Fix/acceptance:** Compiler owner must establish the intended compile header/output under its pinned JVM compiler, then correct table scope/self-check or explicitly document any limited compiler deviation. Keep activation-driven validation rule choice separate from header-driven embeddable table choice. Add a negative parser comparison for the existing fixture plus valid headerv3 counterparts; compile-to-output and independent deserialize must both pass before claiming usable output. This can affect compiler API output, so do not silently alter consensus gates. Evidence: [JVM log](ergo-ser-evidence/pinned-tree-probe-opaque.log), [Rust log](ergo-ser-evidence/rust-benign-probe-corrected.log), pinned TypeSerializer snapshot.

### ES-001 — Strict crate Rustdoc fails on 19 links

**Category:** documentation/build quality; **severity:** P3; **evidence:** REPRODUCED.

`RUSTDOCFLAGS="-D warnings" cargo doc --locked -p ergo-ser --no-deps --all-features` exits101. The19 errors include bracketed `tx[1]`/`output[0]` prose in block_transactions/gates, unqualified read_ergo_tree/contains_header links, private inference/frame/depth helpers, private PoPoW cap links and `[protocol]` in modifier_id. Exact paths/line diagnostics are retained in [strict-docs.log](ergo-ser-evidence/strict-docs.log). Ordinary doc exits0 with warnings; that does not satisfy COMMON's strict gate.

All features/maintainers building strict docs are affected; runtime behavior is unchanged. Correct public qualified links and render code/index notation as code, or use plain text for implementation-only names. Do not disable the lint broadly. Acceptance: the exact strict command succeeds and documented target links resolve. Clippy/tests do not check Rustdoc link resolution; zero doctests do not provide example coverage.

### ES-002 — Public comments/codemap misstate byte, boundary and feature contracts

**Category:** API/maintenance documentation; **severity:** P3; **evidence:** SOURCE_CONFIRMED.

Material examples: [read.rs:20](/home/arkadias/Coding/remote/ergo/ergo-ser/src/ergo_tree/read.rs:20) promises declared-size/all-remaining consumption although success is structural; box mod/candidate/whole descriptions still say sizeless standalone parsing is unavailable though opcode boundary discovery is implemented; spending-proof/JVM UTF8 comments imply verbatim identity where canonical writing applies; constant soft-cap prose describes an exact count reader although current code uses wrapped signed count and the actual reader array gate; HAMT top comments describe older ordering/oracle status; gate/root inference comments describe narrower behavior than the implementation. Crate manifest references old `tests/roundtrip_triage.rs` and implies diagnostics CI execution, while the body is `tests/it/` and the checked feature lane is compile-only. Crate codemap has obsolete flattened paths, roughly16kLOC versus29,548current lines, blanket byte-identity and no-acceptance-gate claims. Address encoding calls original proposition bytes canonical, conflicting with candidate's own accessor contract. Hash/override comments are governed by ES-006/010, not counted again here.

Maintainers/API users relying on these comments can select incorrect framing, trust, identity or verification assumptions. This is a coherent documentation root cause, not eleven additional runtime defects. Update docs from the explicit ownership/version tables, distinguish accepted normalize/opaque/unwritable shapes, and label specification-derived tests versus independent captured oracle tests. Acceptance: every mentioned path/command exists, examples use actual feature/test status, and source/docs agree on observed boundaries. Existing tests check outputs, not prose truth.

### ES-003 — Opcode diagnostics omit nine supported names

**Category:** diagnostics completeness; **severity:** P3; **evidence:** SOURCE_CONFIRMED.

The accepted opcode/payload vocabulary includes0xB6,0xB7 and0xF2–0xF8, but [opcode/types.rs opcode_name](/home/arkadias/Coding/remote/ergo/ergo-ser/src/opcode/types.rs:515) returns `???` for them. Accepted trees therefore lose useful labels in AST/diagnostic consumers in all features. Parse/writer parity tests cover registered payloads but do not assert complete labels. Add actual names and a vocabulary-driven non-unknown name check for every supported tag, while retaining unknown-tag fallback. No parse or evaluation divergence is claimed.

### ES-005 — Batch-proof size sum is unchecked on 32-bit hosts

**Category:** latent portability; **severity:** P3; **evidence:** SOURCE_CONFIRMED, unsupported/unexecuted32-bit consequence.

[batch_merkle_proof.rs:138](/home/arkadias/Coding/remote/ergo/ergo-ser/src/batch_merkle_proof.rs:138) checks each wire-count multiplication but sums `8 + indices_size + proofs_size` without checked additions. Each product can fit a32-bit usize while the sum overflows, contradicting the nearby comment's complete32-bit protection. Debug builds can panic; wrapping release arithmetic can undermine the length gate and later indexing/allocation assumptions. No runtime32-bit test, overflow input or large reservation was made. Current declared release targets are64-bit x86_64 GNU/musl/macOS/Windows; two u32-derived products cannot overflow their64-bit sum. It does not block those current targets or prove peer reachability through proof admission.

Use chained checked additions with typed overflow error; make any32-bit support policy explicit. Validate arithmetic with a bounded helper/boundary test and run a supported32-bit target only if that target is actually added. The neighboring writer's capacity/count casts merit the same future portability review for caller-constructed enormous vectors. Existing native64-bit tests cannot expose this width-dependent error.

## Unresolved questions — excluded from confirmed count

**EP-R1 — Nested sizeless constant-pool bound.** The primitives report's hypothesis was reviewed with pinned authority. Top body read.rs482 saves/sets/restores `VlqReader.constant_pool_len`. `sigma_value/boxed.rs55–99` parses the inner constants and calls `parse_body_with_constants` without scoping that reader bound; opcode/parse.rs271 checks a present bound before type inference uses the supplied inner constants. Scala installs `new ConstantStore(cs)` for its body on the same reader. It restores the old store only after successful root/type validation; validation failures caught as Unparsed can intentionally leave the replacement store. Standalone inner parsing with boundNone differs from inline parsing inheriting outerSome.

This establishes a suspicious ownership mismatch, not a complete admitted input with different verdict. The fully read existing nested tests cover version scope, hard/soft degradation, depths, SBox/SHeader and sidebands, but not valid inner placeholders against unequal outer/inner pool lengths through the complete typing/root/gate path. Top-level placeholder fixtures do not close it. Do not claim accept-invalid/reject-valid or indiscriminately reset failure state. Closure: existing ordinary JVM fixture matrix for no/empty/unequal pool, valid/out-of-range placeholder, success/error/degradation, consumed end and both scopes' final state. If reference semantics differ only after a prior wrap, retain that causal sequence. Owning serializer and primitives reports crosslink this same question; no extra confirmed defect count.

**ES-R2 — Type-validation metadata and compact tuple read order.** Pinned6.0.6 TypeSerializer selects rules1017/1018 at activated3, Rust emits1007/1008 in relevant failure paths. Under unchanged enabled rules a parse direction may match; implications for disabled/replaced validation settings require the validation owner's complete caller/settings proof. Scala compact Pair2 `(T,primitive)` validates the second primitive before recursively reading the first descriptor; Rust's `then_prim` frame defers that primitive until after the child read, despite its exact-order Rustdoc claim. A complete existing fixture showing observable class/consumption/degradation precedence has not been executed here. Closure belongs in ordinary pinned existing type fixtures plus the validation-settings integration; no new malformed operational demonstration is supplied.

Additional evidence limits: known-type/root/method inference intentionally remains partial, so unknown inference cannot establish full reference type acceptance; trust provenance must be checked in every persisted caller; representative stack tests are not a proof for every accepted16,384-deep type's derived equality/clone/drop/write or all runtime threads. These are separately listed limitations, not invented parser divergences.

## Test/oracle coverage by surface

All owned test bodies and cfgs were read. Default execution ran527unit tests,59integration tests and0doctests;19integration tests were ignored. Current targeted execution then ran the six available broad tests, plus the present optional NiPoPoW capture. Broad fixture counts overlap default cases and must not be summed as unique coverage. Twelve ignored transaction-range inputs are absent; the manifest guard also remains unrun because it requires the entire range set. No diagnostics compile-only body is reported as a parity pass.

| Surface | Executed/reviewed evidence and observables | Remaining evidence limits |
| --- | --- | --- |
| Headers/Autolykos/difficulty | Named v1/v2/length/extra-byte tests, two PoW proptests and committed shrink seed; default10+5curated and broad2,545records compare writer/ID/no-PoW fields | Original extraction not freshly run; full malformed/truncation/nonminimal/preimage matrix not independently recaptured; properties are internal consistency |
| Modifier IDs/extensions/AD | Prefix/length/order,255field-value boundary, wire bound properties and opacity checks | No complete live section extraction/accepted normalization campaign; stateful roots/policy elsewhere |
| Block transactions | All serialized versions, fresh per-tx binding store, slice/token/header/group sideband regressions and missing input/output structure handling | Empty writer/read asymmetry is deliberate construction test; full block-version/activation malformed EOF matrix not recaptured |
| Tx/signing/token table | Two default captured files13records; three broad corpora200/1,000/335records; bytes-to-sign reconstruction and ID; unused/duplicate token table, bad index, high-bit/zero amounts regressions | Twelve missing ranges; no full-chain replay; extracted self roundtrip is not independent raw JVM rejection-class proof |
| Boxes/candidate/whole/indexed | Default and broad31captured boxes; sizeless streamed boundaries, accepted variants, token cap, raw/canonical normalized tree/register tests; constructor/mutation probe; root pinned Scala ordinary whole-box/reconstructed-ID comparison at activation1/2/3 | ES-007/008/012; every truncation/after-failure/caller storage seam not closed; no canonical-chain occurrence demonstrated |
| SpendingProof/extensions/HAMT | Checked raw extension normalization; identity group/UTF8/evaluated-value captures;4/5transition and nine Java/Scala HAMT oracle vectors, byte signed hashing | ES-011; full256key/collision-order independent campaign not run; generator full read belongs workspace |
| ErgoTree framing/wrap/gates | Declared size mismatch/wrapped signed size, root/hard-soft classes, future headers, nested trust, checkpoint/sideband truncation, reused scope regressions;73broad captured trees | Complete Cartesian version/activation/size/segregation/trust/root settings not independently captured; EP-R1/ES-R2 |
| Hash/template | Current pinned JVM existing normalized/opaque cases independently distinguish verdict, consumed, cached bytes, serialization, template and root; Rust keys/IDs | ES-006; no populated index migration/rollback/API lookup current test |
| Opcodes/walk/segregation | All known payload roundtrips/preorder node IDs; append-only segregation and Relation2 dedup tests; exhaustive65,536registry-ID combinations against fixture; captured numeric/select verdict/consumption | Same-stack payload cases do not prove JVM support for every AST; ES-003/004; method registry signatures regenerated by6.0.6 but broad6.0.2resolution capture isn't a full signature oracle |
| Root/type inference | Captured root-gate cases/responses; method signatures and parameter substitution/function binder tests | Generated signature source/data provenance reviewed by workspace; unknown inference and active rules require owner oracle closure |
| Sigma type | Every descriptor/compact tuple/coll/function/type-var case; iterative parser and high-depth test; general0/1tuple acceptance vs writer refusal retained;5JVMUTF8 replacement goldens | Type write/equality/drop are recursive and deep tests use large stacks; ES-R2 order/metadata; source-only value/UTF8 expectations distinguished from independent oracle capture |
| Sigma values/bigints/arrays/AVL | Signed/unsigned32byte limits, sign padding/zero, packed booleans/strings/options/tuples, AVLflags/digest lengths, SBox/SHeader nested gates; captured BigInt cap fixture assertions | Some inline SBigInt goldens are specification-derived rather than external captures; original cap generator not rerun; no universal large-width performance/stack proof |
| SigmaBoolean/shared depth | Captured decode_depth.tsv verdicts/consumption;110shared level, mixed boxes/expressions/registers/extensions, Cthreshold/SECprefix hard-vs-soft classes; representative4MiB decode worker tests | ES-009 initial capacity; no allocator RSS/concurrency/peeradmission proof or exhaustion run |
| Addresses | Checksum/wrongnetwork/short input/type route/P2SH prefix/P2S/P2PK golden and property cases; API selected caller validation ownership traced | Arbitrary public raw encoder/decoder content validation intentionally caller-owned; all offcurve/JVMaddress API behavior not recaptured |
| PoPoW/NiPoPoW/batch | Field caps/order/EOF, empty marker/nonzero side normalization, curated Scala binary and present optional capture (`m6,k10,prefix104,tail9`) both run | Proof validity/linkage/duplicate reduction belongs crypto/validation; full conversion/admission ownership not audited here; ES-00532-bit not supported/tested |
| SANTA paired corpus |27families,189entries:77Box,95Transaction,4Constant,13SigmaBoolean;108accept/81reject. All paired name/counts/hex structurally checked, existing test ran | Captured6.0.6, not freshly regenerated. Harness collapses all rejection classes and does not capture consumed count; strict EOF affects accepted verdict; it cannot prove rule/degradation metadata |
| Diagnostics/replay adapters | diagnostics body fully read and COMPILE_ONLY; parses/errors printed/continued; exact corpus prerequisites classified | Print-only summary is not an acceptance gate. Complete ergo-difftest generator/oracle-adapter review is owned by its audit/workspace, not inferred from local passing fixtures |

No new tests were committed. Temporary probe inputs derive from existing named unit fixtures/helpers and remain in evidence. The Rust isolated probe was seeded with the repository lock after a fresh offline resolution guard found newer cached packages; no mismatched dependency version was executed. A subsequent small probe compile typo was corrected only in evidence. Both initial logs remain and are classified independently of final reproduced results.

## Verification accounting

Complete commands, environment, tested revision, statuses, duration and logs: [commands.json](ergo-ser-evidence/commands.json). All Cargo package commands used existing pinned dependencies.

| Command / log | Result and scope |
| --- | --- |
| `cargo test --locked -p ergo-ser` / baseline.log | PASS0;527unit,59integration,19ignored,0doctests |
| `cargo test --locked --no-run -p ergo-ser --features diagnostics` | COMPILE_ONLY0; no diagnostics assertions executed |
| `cargo clippy --locked -p ergo-ser --all-targets --all-features -- -D warnings` | PASS0 |
| `cargo test --locked -p ergo-ser --doc` | PASS0;0examples executed |
| Strict all-feature Rustdoc | FAIL101;19errors, ES-001 |
| `cargo doc --locked -p ergo-ser --no-deps` | PASS0 with warnings; prompt command executed |
| `cargo check --locked -p ergo-ser --no-default-features` | COMPILE_ONLY0 |
| Normal/feature Cargo trees | PASS0; dependency/feature resolution inspection |
| `cargo test --locked -p ergo-ser --test it roundtrip_broad -- --ignored --nocapture` | PASS0;3tests,2,545headers/73trees/31boxes |
| Same command with exact `tx_roundtrip_1_200`, `tx_roundtrip_1_1000`, `tx_roundtrip_205000_205200` filters | PASS0;1test each;200/1,000/335tx records plus signing-byte checks |
| Optional `captured_scala_proof_roundtrips_byte_identical -- --nocapture` | PASS0;1actual capture, present prerequisite; not vacuous |
| Current pinned Scala existing-tree probe / pinned-tree-probe-opaque.log | PASS0;3existing input families×3activation scopes; logs distinguish cache/serialized/template and rejection |
| Isolated Rust existing-fixture probe / rust-benign-probe-corrected.log | PASS0;bounded hash/constructor/mutation/extension/sizeof assertions; baseline versions |
| Initial fresh isolated offline lock resolution | UNAVAILABLE for intended pinned run; guard stopped before execution, newer cached dependencies not used. Elapsed/guard exit not recorded; subsequent corrected run has full metadata |
| Initial baseline-lock probe compile | FAIL101 from temporary probe typo; corrected evidence-only; not a crate build defect |

Shared gates were already coordinated at this revision and were not repeated: fmt, workspace Clippy, nextest7,629pass/98skip, doctests, deny, documented RUSTSEC-2025-0141 exception audit, machete and cost/integrity checks passed; strict workspace Rustdoc failed. Root later recovered the Node tooling and its dashboard gate passed63/63. See [shared-evidence/results.json](shared-evidence/results.json). Advisory exceptions and external generator closure remain the workspace report's responsibility.

**UNAVAILABLE:**12missing mainnet transaction ranges, precisely listed in the machine ledger. No live extraction was run. **NOT_RUN:** diagnostics campaign, full manifest guard, original generators/live extraction, full differential campaign, full-chain replay, release/native macOS/Windows/musl runs,32-bit, Miri/sanitizers, allocation/RSS benchmarks or exhaustion demonstrations. Supported native checks require matching hosts; this Linux build cannot certify them. Installed JVM availability was established, so unexecuted broader oracle work is NOT_RUN, not an unavailable-tool excuse.

Next ordinary evidence, after relevant owner review: rerun the exact failed strict-doc command following ES-001; run diagnostics only with its corpus denominator explicitly counted; exact ignored range filters only after each prerequisite exists. A full `--ignored` command presently attempts missing inputs and is not an honest parity gate. Existing fixture oracle recapture must retain pinned version/source metadata and compare verdict/class/consumption/canonical/ID observables independently; a fixed point alone is insufficient.

## Remediation order and readiness

1. Establish shared raw/canonical ownership for ES-006/007/012. Correct helper keys/canonical checked construction and preserve the distinct parsed whole-box identity contract. Reconcile REST-JSON Preserve and wallet/indexer storage, then exercise apply/rollback/rebuild/query and ID/signing integration on existing normalized/opaque fixtures. Migration decisions must follow the exact persisted-key contract.
2. Close ES-008 mutable-cache invariants and ES-011/004 writer bounds with focused public-API tests. Preserve accepted wire forms and reference evaluated node identity; narrow construction failure must remain typed and recoverable.
3. Bound ES-009 initial reservations without changing valid widths or hard/soft read order. Use source/allocation-strategy and bounded regression evidence; complete admission/concurrency analysis before assigning a remote RSS consequence.
4. Compiler owner resolves ES-010's claimed self-check contract from its pinned compilation authority. Keep consensus reader/table/header semantics distinct from the compiler escape hatch.
5. Correct strict docs, contract comments/codemap and opcode labels. ES-005 is a small defensive portability fix, not evidence of a current64-bit node vulnerability.
6. Close EP-R1 and ES-R2 through ordinary existing pinned reference/settings fixtures before changing scoped failure behavior. Complete downstream trust/stack/proof seams, shared generator/differential closure and supported-native/release evidence separately.

The authored inventory is complete, all available bounded crate captures passed, and current independent JVM probes substantiate the reported hash and override distinctions. The confirmed construction/query/writer defects prevent a readiness claim for this crate's stated public boundary, so NOT_READY is the appropriate scoped judgment. External caller/generator/dependency validation remains owned elsewhere and limits any broader node/reference-quality claim; missing scenarios and unresolved reader hypotheses are not represented as demonstrated consensus failures.
