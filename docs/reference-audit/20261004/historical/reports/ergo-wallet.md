# ergo-wallet audit — 2026-10-03

## Scope and baseline

Revision `5d62fd5851e74fcb965b4aba50e1b423127f46f1`, branch main, Linux x86_64, Rust/Cargo 1.95.0. Review only. The pre-existing README modification and untracked audit documentation remain user/root-owned. No source, tests, configuration, reference or dependency edits were made. This ignored session directory contains local report/evidence artifacts.

Independent inventory and acknowledged complete reads cover **57 authored files, 15,490 lines, 605,655 bytes (56 Rust files and Cargo.toml)**, including comments, CLI branches, ignored tests and the two test-utils targets. No owned authored exclusions or unread/partial files remain. [Machine ledger](ergo-wallet-coverage.json), [hash/range verification](ergo-wallet-evidence/coverage-validation.json) and source questions are durable. The ledger adds 65 shared rows with exact-hash reuse of API/NODE full reads, STATE wallet owner reads, pinned Scala sources and capture integrity. Shared dependency statuses retain their actual provenance; fixture parsing is not an independent producer verdict.

Authorities: COMMON, assignment, crate prompt, CONTRIBUTING, compatibility and codemap; [BIP32 primary specification](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki); pinned sigma-state v6.0.6 `ab0b15ceb9d34f2ccd6e68e3e2a8aa27cd16a042`; pinned Ergo Scala v6.0.5 `5528ef569a41ebccbc8658212e6ee3c97d990b96` cache/predicate source. ExtendedSecretKey/ExtendedKey worktree HEAD differs from the tag, so both actual file hashes were independently compared with tag content before use. [Reference pins](ergo-wallet-evidence/reference-key-pins.json) and [source receipts](ergo-wallet-evidence/reference-source-reads.json) preserve this distinction. Captured signing/multisig files have complete duplicate-key-rejecting integrity receipts and fully reviewed consumers, but named extraction tools/transcripts are absent here.

## Contract map

| Boundary | Owned contract and production seam | Evidence / limit |
| --- | --- | --- |
| Phrase → seed → key | BIP39 checksum, strength, normalization and passphrase; fixed-width modern master/children; narrowly historical child encoding | Mnemonic/BIP32/path/address tests; independent leading-zero vector below. Rare invalid-child/IL=0 and class-boundary parity remain source questions. |
| Secret file → unlocked | Metadata checked before KDF; PBKDF2-HMAC-SHA512/AES-GCM authentication; 64-byte plaintext seed; metadata chooses separate modern/legacy type | Wrong password/tamper tests and disposable reopen proof; ignored Scala encryption/storage parity prerequisites are not PASS. |
| Lifecycle | open yields presence-derived Uninitialized/Locked; successful first init/restore writes a Locked identity; unlock installs key; lock erases long-lived key | Public repeated restore violates this diagram. NODE guards repeated init/restore; NODE-005/006 own downstream rollback/cleanup defects. |
| Key cache → ownership/address | Canonical P2PK tracked scripts, visible/change ownership, hydration from committed STATE rows | Live third-key filter differs from persisted rebuild; mutation helpers are not transactional. STATE Confirmed-only unspent reader excludes immature/spent and custom scan-only rows. |
| Selection/build → sign | Unique input subset, checked amounts, minimum/dust/change/token rules; coherent ordered inputs/data/header/parameter context | Package tests and NODE native/compat bridge full reads. Public selectors/context helpers require stronger caller invariants; final semantic/cost validation remains authoritative. |
| Proof → hints | OS entropy in production; DLog/DHT equations; FS binds proof message; AND/OR/threshold traversal, positions, simulation, partial rounds | 11 captured Scala verifier cases plus Rust consistency/distributed tests. Caller-supplied OwnCommitment is secret nonce material; it is reusable and cloneable. No misuse demonstration performed. |
| Scan | Restricted typed register/token predicates, intentional Scala Long→Int equality quirk; monotonic scan IDs, names and reserved scans | Pinned ScanningPredicate and NODE guards/store reader; accepting R0/R2/R3 does not establish observable mismatch with Scala's restricted comparable types. |
| CLI/features | Mainnet/testnet output; NODE devnet uses testnet chain-spec prefix; TTY/stdin/file/explicit-danger argv custody; test-utils deterministic RNG separated from fixed production OsRngBackend | CLI smoke, manifest/feature tree and full branch reads; non-host platforms and complete transient-memory erasure remain unproved. |

## Confirmed findings

### WALLET-001 — legacy master strips bytes that Scala retains

[Primary source](/home/arkadias/Coding/remote/ergo/ergo-wallet/src/extended_key.rs:284).

**P2 · recovery compatibility · REPRODUCED.** `extended_key.rs:279–293` promises identical master derivation then strips leading zeros from the legacy master's 32-byte HMAC result. The pinned Scala `ExtendedSecretKey.scala:94–102` retains all 32 bytes in both modes; only children at `:70–81` use variable-length legacy storage. Rust's first hardened HMAC consequently receives shorter parent bytes at `extended_key.rs:338–343`.

Official BIP32 vector3 is an ordinary 64-byte public seed with a leading-zero master. [Rust probe](ergo-wallet-evidence/benign-probe.log) reports modern32/legacy31 master bytes and different first hardened public keys. [Independent Scala6.0.6 run](ergo-wallet-evidence/pinned-key-reference.log) reports master32 in both modes and the modern Rust first-child public key in both. Exact build/run and tag receipts are retained. No real wallet or actual fund loss was demonstrated.

Production reachability is source-confirmed: `storage.rs:451–459` selects Legacy from restored/missing-field metadata; NODE `wallet_boot.rs:211–214` derives EIP3 beginning44'. Thus a legitimate matching legacy seed can derive different restored addresses. Existing tests cover later child trimming but not a leading-zero master against Scala. Preserve 32-byte legacy **master** bytes; retain historical child trimming. Acceptance: vector3 and existing legacy child-zero vectors must agree with pinned Scala, including complete EIP3 and pre-EIP3 restore paths. Assess migration for wallets created by this incorrect Rust behavior before changing persisted derivation outcomes.

### WALLET-002 — advertised boolean cannot select legacy child derivation

[Primary source](/home/arkadias/Coding/remote/ergo/ergo-wallet/src/lib.rs:41).

**P2 · public API compatibility · SOURCE_CONFIRMED.** `lib.rs:41–44` advertises `ExtendedSecretKey::derive_master_key(seed, true)` for legacy wallets, but `extended_key.rs:61–64` discards the flag and returns the always-modern type. Subsequent derive_child/derive_at_path retain modern byte shape. SecretStorage explicitly chooses ExtendedSecretKeyLegacy, so this is a public-helper contract defect distinct from WALLET-001, not evidence that all node restores ignore their metadata.

Return a mode-carrying master type or remove the misleading flag and document the separate legacy API with migration guidance. Regression: the advertised public route must reproduce an existing leading-zero **child** legacy vector, not only equal master public keys. Existing equal-master tests cannot detect lost mode information.

### WALLET-003 — secret nonce hints have no enforced one-message lifecycle or erasure

[Primary source](/home/arkadias/Coding/remote/ergo/ergo-wallet/src/proving/hints.rs:57).

**P2 · custody/proof API · SOURCE_CONFIRMED.** `proving/hints.rs:57–66` stores OwnCommitment randomness as ordinary `[u8;32]`, derives Clone, and has no Zeroize/Drop. `all_for_input:199–207` clones it. The correctly redacted Debug implementation at68–81 does not erase these copies. Schnorr `:85–105`, DHT and compound prover reuse matching image/position nonce material from a borrowed bag; they neither consume the nonce nor bind its ownership to a single message/round.

A caller can retain or clone an OwnCommitment and submit it for another message. The response equation in Schnorr source makes reused or disclosed randomness a key-custody hazard, even when each proof self-verifies. Existing consistency tests explicitly cover same-message retries; no cross-message nonce recovery or memory scraping was executed, and Clone alone does not prove production disclosure. This finding applies to public hint-consuming APIs and authenticated compat signing, not an unauthenticated signing bypass.

Give secret nonce material an erased, provenance-aware single-round abstraction with an explicit message/round binding and safe same-message retry semantics; restrict cloning to controlled erased storage. Document trusted caller responsibility where the API deliberately imports locally generated secret hints. Add tests that reject a bag's reuse for a different message, retain supported same-message retries, and verify clone/drop handling. Do not conflate this fix with the separate API Debug exposure/API-010 or NODE public-hint bucket/NODE-012 addenda.

### WALLET-004 — named secret file can publish a partial wallet

[Primary source](/home/arkadias/Coding/remote/ergo/ergo-wallet/src/storage.rs:571).

**P2 · custody durability/recovery · SOURCE_CONFIRMED with bounded reopen evidence.** `storage.rs:571–578` creates the final UUID file with mode0600 then write_all; it has no temporary completed-file publication, sync_all/parent-directory durability step, or cleanup after a write error. A mid-write error can leave a named partial file even though init/restore returns Err. `lock_state:285–296` classifies its presence as Locked. Non-Unix582 uses ordinary fs::write and lacks the Unix creation permission guarantee.

[Disposable public-vector probe](ergo-wallet-evidence/storage-reopen-probe.log) simulates a truncated named file: reopen is Locked, metadata load and unlock fail. Wrong password and unsupported PRF fail closed in the same bounded check. This proves restart interpretation of a partial artifact; no physical crash/disk-full event or Windows permission execution was performed. NODE boot consequently cannot treat a named file as a complete initialized wallet, and lifecycle guards prevent a routine second init over it.

Publish through a restricted temporary file only after complete write and required synchronization, atomically establish the final file without overwrite, synchronize the directory for the supported durability contract, and clean failed temporary state. Preserve UUID/Scala JSON compatibility and define Windows ACL policy. Test injected ordinary write/sync failures and reopen at each publication boundary in disposable directories; add platform acceptance, without assuming authenticated encryption repairs truncation.

### WALLET-005 — third tracked key exposes the hidden master until hydration

[Primary source](/home/arkadias/Coding/remote/ergo/ergo-wallet/src/state.rs:212).

**P2 · visible-address consistency · REPRODUCED/source-confirmed production seam.** WalletState `state.rs:204–222` hides the first key only when the total is exactly2. Adding a third key yields three visible addresses. Pinned Scala WalletCache hides the master when a subsequent EIP3 key exists for any total greater than1. NODE `support/key_derivation.rs:110–120` persistently excludes index0/empty-path master, while `:206–214` updates this live cache with insert_tracked_pubkey. Subsequent hydration takes the persisted visible list.

The public-key probe reports visible counts1,1,3 for three distinct valid keys. A routine authenticated third-key derivation can therefore produce a live address list inconsistent with the committed list and after lock/reopen hydration. No invalid key or chain transaction is needed. Store path metadata in the cache or derive visibility from the committed policy; avoid total-count inference. Regression: first EIP3 setup, third/further/manual paths, master-only and pre-EIP3 states must match pinned policy before/after reopen. Existing two-key-only tests miss the discontinuity.

### WALLET-006 — tracked-key mutations violate their atomic cache contract

[Primary source](/home/arkadias/Coding/remote/ergo/ergo-wallet/src/state.rs:163).

**P2 · public state integrity · REPRODUCED.** `state.rs:158–180` promises atomic rebuild but inserts the map before fallible address encoding, appends the new tree without removing a replaced old key's tree, and clears visible addresses during rebuilding. Remove at187–200 removes a script even if another index retains the same public key. Hydrate at232–267 clears current caches before fallible reconstruction.

The benign probe replaces one valid key at the same index: one cached key and two tracked scripts remain. An invalid SEC1 key returns Err but leaves one cached key and one tracked tree. The exact caller validation makes malformed-key production reachability conditional; no canonical node scan misclassification incident is claimed. Stage all derived caches from the proposed complete map and swap them on success; rebuild duplicate ownership from values rather than incremental set removal. Test replacement/shared key removal and fallible insert/hydration preserving previous valid state.

### WALLET-007 — repeated library restore retains the old unlocked identity

[Primary source](/home/arkadias/Coding/remote/ergo/ergo-wallet/src/storage.rs:362).

**P2 · storage lifecycle · REPRODUCED.** Public init343–353/restore362–371 have no existing-state guard. persist_seed525–588 writes a new random UUID file and replaces cached metadata but leaves self.unlocked unchanged. A second successful restore while unlocked reports Unlocked with the old seed, the new cached encrypted seed, and multiple selectable files.

The public BIP39 probe restores/unlocks a known vector, then restores it with a different public passphrase/password: files2, previous seed still matches, new seed does not. It deletes its disposable directory afterward. NODE commands/admin.rs154–160/199–205 reject repeated init/restore, so no REST reinitialization claim follows. Enforce legal transitions inside SecretStorage and return a typed existing-wallet error without modifying either identity; define a separate explicit replacement protocol if required. Regression: all states plus every failure leave consistent disk/cache/unlocked identity. Existing first-restore tests do not exercise repeated initialization.

### WALLET-008 — selector reports duplicate summaries as a funded subset

[Primary source](/home/arkadias/Coding/remote/ergo/ergo-wallet/src/box_selector/default.rs:23).

**P2 · public selection accounting · REPRODUCED.** DefaultBoxSelector `box_selector/default.rs:23–42` appends every supplied ID and counts each summary, including repeats; ERG/token sums saturate rather than reject overflow. BoxSelector's49–59 contract returns a valid funding subset or error without an ID-uniqueness precondition.

The bounded public helper probe supplies one10-nanoERG ID twice against target15; select succeeds with the same ID twice and change5. These inputs cannot fund that transaction. Actual STATE wallet rows are uniquely keyed; NODE native BoxIds reject duplicates and final semantic validation rejects invalid transactions. No invalid spend acceptance was demonstrated. Reject repeated IDs and arithmetic overflow at the public boundary (including conflicting summaries for the same ID); apply builder limits before proof work. Tests should cover duplicate/conflicting IDs and overflow without relying solely on the downstream validator.

### WALLET-009 — required strict documentation gate fails

[Primary source](/home/arkadias/Coding/remote/ergo/ergo-wallet/src/scan/predicate.rs:101).

**P3 · documentation/tooling · SOURCE_CONFIRMED.** Current strict no-dependency/all-feature Rustdoc fails101 with four primary diagnostics: predicate public links to private equals_filter and parse_constant, unresolved DerivationPath in storage, and bare URL in derivation. [Complete log](ergo-wallet-evidence/rustdoc.log) was read. Clippy success and zero doctests do not imply this gate passes. Correct visibility-aware links and URL markup, then rerun the exact recorded strict command; no API behavior change is required.

## Cross-owner additions and preserved ownership

API-010 is recorded in the API report addendum: derived Debug of HintDto/TxHintsBagDto exposes OwnCommitment.secret rather than using wallet's redacted representation. NODE-012 is recorded in the NODE addendum: publicHints admits OwnCommitment and reclassifies it into secret hints before compat signing. These are separate actionable causes, excluded from the nine wallet-owned confirmed findings. No production logging, unauthenticated access or key-extraction demonstration is claimed.

NODE-002 owns wallet writer/rescan shutdown; NODE-004 manual derivation head; NODE-005 post-decrypt boot rollback; NODE-006 rescan guard cleanup; NODE-007 direct transaction quick-repair policy. This report independently corroborates underlying wallet contracts and does not duplicate those counts. SER ES007/ES012 distinguish a parsed whole-box cached wire identity from a newly assembled candidate's canonical identity; shared box-reference receipt confirms that distinction, not a canonical chain occurrence. Supplied input/data IDs and Preserve-mode consumers require identity-specific integration regression, without normalizing every box indiscriminately.

## Coverage, commands and gaps

All commands use this revision, cwd repository root, locked dependencies and six build jobs. [Results/commands](ergo-wallet-evidence/results.json) and complete logs retain exits/toolchain/features/timing.

| Check | Actual result |
| --- | --- |
| cargo test --locked -p ergo-wallet | PASS181, failed0, ignored8; bin/doctest0 |
| same --features test-utils | PASS238, failed0, same ignored8; 57 additional unique tests |
| package Clippy all targets/all features -D warnings | PASS |
| package doctests | PASS0 |
| strict Rustdoc all features/no-deps -D warnings | FAIL101, four primary diagnostics |
| no-default-features check | COMPILE_ONLY PASS; crate has no default feature definition |
| production dependency feature tree | PASS captured; test-utils selects no production RNG backend |
| bounded public helper/storage probes | PASS execution; defects observed as stated; simulated partial file, no physical failure |
| independent Scala6.0.6 key vector | PASS execution; legacy divergence observed |

Shared unchanged workspace gates are reused:7629PASS98skipped, fmt/Clippy/deny/machete/advisory-policy/cost tooling passing, strict workspace Rustdoc failed. No shared gate was rerun solely for this report. Scoped baseline/feature tests are separately executed, not inferred from feature-unified workspace results.

All eight ignored bodies were read: one legacy intermediate placeholder, one Scala selector TODO, three storage oracle cases (two missing captures and one manual print-only interoperability path), two AES cipher/tag placeholders, and one pre1627 address extraction prerequisite. None was enabled without evidence. Modern BIP39/path/address and AES same-Rust tests pass; that is not bidirectional Scala storage interoperability. Corpus README prose says8 but capture has11 verifier cases; multidistributed Rust tests at multi_sig_inline2343–2446 genuinely test two-party AND/threshold completion despite stale earlier comments. Captured multisig tests pin selected challenge/hint properties, not every response/position/commitment against a freshly generated oracle.

Explicit unproved/source boundaries: IL=0 is rejected by Rust child SecretKey parsing although CKDpriv permits it when child is nonzero; class-preserving retry differs from pinned Scala's raw increment at the extremely rare boundary; no forced HMAC experiment was run. Public compound AST can reach nested TrivialProp unreachable branches and unchecked child-position casts; ordinary reduction/serializer shape and production reachability were not independently established. Public signing/context helpers mostly check counts, while NODE supplies lookup/semantic/cost context; count-only proof success is not a valid chain transaction verdict. Scan comparable types and intentional Long quirk were checked against the selected pinned predicate source; unsupported register matching remains a contract limitation rather than a proven new divergence.

Residual custody: long-lived master/storage/registry erasure and Debug redaction are present, but bip39's production dependency lacks its zeroize feature, phrase/entropy/seed temporaries, TTY originals, HMAC internal buffers, proof scalars and nonce clones retain unproved erasure. Zeroization alone does not establish swap/crash-dump protection. No memory scrape, nonce/key recovery, native Windows/macOS, actual crash/storage exhaustion, all public invalid AST shapes, sustained-load distribution or chain fund incident was performed. These are explicit limitations, not passing evidence.

Next external validation: restore missing pinned generators/captures, then run selected ignored cases only after replacing placeholders with checked independent outputs; in particular `cargo test --locked -p ergo-wallet --test it storage_oracle -- --ignored --nocapture` is NOT_RUN and remains unsuitable until its manual-only case becomes an executable Scala verifier assertion. Establish Rust-produced proof → pinned Scala verification for DLog/DHT/AND/OR/threshold/partial rounds, including safe wrong-context/hint rejection. Use existing public fixtures and disposable directories, never operational secrets.

## Remediation and readiness

Fix legacy master shape and the advertised mode API first, with historical-wallet migration analysis and independent vectors. Separate nonce ownership/message lifecycle, API Debug redaction and public-hint admission fixes; preserve supported local secret hints and same-message retries. Make secret-file publication/durability explicit and restart-safe. Rebuild caches transactionally from path-aware state, enforce SecretStorage transitions and selector input/accounting invariants, then repair Rustdoc and supply missing independent parity evidence.

**NOT_READY.** Owned read coverage is complete; nine wallet findings (eightP2/oneP3), separate cross-owner additions and material external parity/durability/custody gaps prevent a reference-quality readiness claim. No consensus split, unauthenticated exploit, actual private-key disclosure or historical fund loss has been demonstrated.
