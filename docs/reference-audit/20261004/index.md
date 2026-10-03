# Reference audit review record

Snapshot: 2026-10-03T22:35:38.548204+00:00.

This record connects 160 original findings to 157 causes, owner dispositions and published draft PRs. It is a remediation record, not a current full source review or a reference-node certification.

The historical audit reviewed `5d62fd5851e74fcb965b4aba50e1b423127f46f1`. Remediation was revalidated against `71bb70165bb0b945b097b170f69fd0cc96b325e4` before fixes. The source moved substantially between those revisions.

## Current owner dispositions

| Reported status | Original findings |
|---|---:|
| already_fixed | 28 |
| fixed | 128 |
| remaining_evidence | 4 |

Statuses are copied from the owners. `remaining_evidence` can mean partial evidence, an external fixture prerequisite, or work still in progress; the full owner record preserves that distinction. A published draft is not merged work. Missing receipt fields do not imply a PASS.

The full ST009 owner record distinguishes cached-state checks, captured activation costs and any remaining historical prerequisites. The historical fuzz ledger retains HASH_ONLY files and does not establish executed decoder or provenance checks.

## Finding and PR index

| Original ID | Cause | Owner status | Historical report | Draft PRs |
|---|---|---|---|---|
| EP001 | EP001 | fixed | [ergo-primitives](historical/reports/ergo-primitives.md) | [#524](https://github.com/arkadianet/ergo/pull/524) |
| EP002 | EP002 | fixed | [ergo-primitives](historical/reports/ergo-primitives.md) | [#524](https://github.com/arkadianet/ergo/pull/524) |
| EP003 | EP003 | fixed | [ergo-primitives](historical/reports/ergo-primitives.md) | [#524](https://github.com/arkadianet/ergo/pull/524) |
| EP004 | EP004 | fixed | [ergo-primitives](historical/reports/ergo-primitives.md) | [#524](https://github.com/arkadianet/ergo/pull/524) |
| ECSP001 | ECSP001 | fixed | [ergo-chain-spec](historical/reports/ergo-chain-spec.md) | [#510](https://github.com/arkadianet/ergo/pull/510) |
| ECSP002 | ECSP002 | fixed | [ergo-chain-spec](historical/reports/ergo-chain-spec.md) | [#510](https://github.com/arkadianet/ergo/pull/510) |
| ECSP003 | ECSP003 | fixed | [ergo-chain-spec](historical/reports/ergo-chain-spec.md) | [#517](https://github.com/arkadianet/ergo/pull/517) |
| ECSP004 | ECSP004 | fixed | [ergo-chain-spec](historical/reports/ergo-chain-spec.md) | [#517](https://github.com/arkadianet/ergo/pull/517) |
| DIFF01 | DIFF01 | fixed | [ergo-difftest](historical/reports/ergo-difftest.md) | [#543](https://github.com/arkadianet/ergo/pull/543) |
| DIFF02 | DIFF02 | remaining_evidence | [ergo-difftest](historical/reports/ergo-difftest.md) | [#562](https://github.com/arkadianet/ergo/pull/562) |
| DIFF03 | DIFF03 | remaining_evidence | [ergo-difftest](historical/reports/ergo-difftest.md) | [#562](https://github.com/arkadianet/ergo/pull/562) |
| DIFF04 | DIFF04 | fixed | [ergo-difftest](historical/reports/ergo-difftest.md) | [#531](https://github.com/arkadianet/ergo/pull/531) |
| DIFF05 | DIFF05 | fixed | [ergo-difftest](historical/reports/ergo-difftest.md) | [#531](https://github.com/arkadianet/ergo/pull/531) |
| DIFF06 | DIFF06 | fixed | [ergo-difftest](historical/reports/ergo-difftest.md) | [#531](https://github.com/arkadianet/ergo/pull/531) |
| DIFF07 | DIFF07 | fixed | [ergo-difftest](historical/reports/ergo-difftest.md) | [#531](https://github.com/arkadianet/ergo/pull/531) |
| DIFF08 | DIFF08 | fixed | [ergo-difftest](historical/reports/ergo-difftest.md) | [#540](https://github.com/arkadianet/ergo/pull/540) |
| DIFF09 | DIFF09 | fixed | [ergo-difftest](historical/reports/ergo-difftest.md) | [#543](https://github.com/arkadianet/ergo/pull/543) |
| DIFF10 | DIFF10 | fixed | [ergo-difftest](historical/reports/ergo-difftest.md) | [#558](https://github.com/arkadianet/ergo/pull/558) |
| DIFF11 | DIFF11 | fixed | [ergo-difftest](historical/reports/ergo-difftest.md) | [#558](https://github.com/arkadianet/ergo/pull/558) |
| DIFF12 | DIFF12 | fixed | [ergo-difftest](historical/reports/ergo-difftest.md) | [#564](https://github.com/arkadianet/ergo/pull/564) |
| DIFF13 | DIFF13 | fixed | [ergo-difftest](historical/reports/ergo-difftest.md) | [#564](https://github.com/arkadianet/ergo/pull/564) |
| DIFF14 | DIFF14 | fixed | [ergo-difftest](historical/reports/ergo-difftest.md) | [#558](https://github.com/arkadianet/ergo/pull/558) |
| DIFF15 | DIFF15 | already_fixed | [ergo-difftest](historical/reports/ergo-difftest.md) | — |
| DIFF16 | DIFF16 | fixed | [ergo-difftest](historical/reports/ergo-difftest.md) | [#568](https://github.com/arkadianet/ergo/pull/568) |
| DIFF17 | DIFF17 | fixed | [ergo-difftest](historical/reports/ergo-difftest.md) | [#531](https://github.com/arkadianet/ergo/pull/531) |
| ES006 | ES006 | fixed | [ergo-ser](historical/reports/ergo-ser.md) | [#500](https://github.com/arkadianet/ergo/pull/500) |
| ES007 | ES007 | fixed | [ergo-ser](historical/reports/ergo-ser.md) | [#504](https://github.com/arkadianet/ergo/pull/504) |
| ES012 | ES012 | fixed | [ergo-ser](historical/reports/ergo-ser.md) | [#504](https://github.com/arkadianet/ergo/pull/504) |
| ES008 | ES008 | already_fixed | [ergo-ser](historical/reports/ergo-ser.md) | — |
| ES011 | ES011 | already_fixed | [ergo-ser](historical/reports/ergo-ser.md) | — |
| ES004 | ES004 | fixed | [ergo-ser](historical/reports/ergo-ser.md) | [#518](https://github.com/arkadianet/ergo/pull/518) |
| ES009 | ES009 | fixed | [ergo-ser](historical/reports/ergo-ser.md) | [#518](https://github.com/arkadianet/ergo/pull/518) |
| ES010 | ES010 | fixed | [ergo-ser](historical/reports/ergo-ser.md) | [#516](https://github.com/arkadianet/ergo/pull/516) |
| ES001 | ES001 | already_fixed | [ergo-ser](historical/reports/ergo-ser.md) | — |
| ES002 | ES002 | fixed | [ergo-ser](historical/reports/ergo-ser.md) | [#518](https://github.com/arkadianet/ergo/pull/518) |
| ES003 | ES003 | fixed | [ergo-ser](historical/reports/ergo-ser.md) | [#518](https://github.com/arkadianet/ergo/pull/518) |
| ES005 | ES005 | fixed | [ergo-ser](historical/reports/ergo-ser.md) | [#518](https://github.com/arkadianet/ergo/pull/518) |
| API001 | API001 | already_fixed | [ergo-api](historical/reports/ergo-api.md) | — |
| API002 | API002 | already_fixed | [ergo-api](historical/reports/ergo-api.md) | — |
| API003 | API003 | already_fixed | [ergo-api](historical/reports/ergo-api.md) | — |
| API004 | API004 | already_fixed | [ergo-api](historical/reports/ergo-api.md) | — |
| API005 | ES006 | fixed | [ergo-api](historical/reports/ergo-api.md) | [#505](https://github.com/arkadianet/ergo/pull/505) |
| API006 | API006 | fixed | [ergo-api](historical/reports/ergo-api.md) | [#549](https://github.com/arkadianet/ergo/pull/549) |
| API007 | API007 | fixed | [ergo-api](historical/reports/ergo-api.md) | [#548](https://github.com/arkadianet/ergo/pull/548) |
| API008 | API008 | fixed | [ergo-api](historical/reports/ergo-api.md) | [#551](https://github.com/arkadianet/ergo/pull/551) |
| API009 | API009 | fixed | [ergo-api](historical/reports/ergo-api.md) | [#552](https://github.com/arkadianet/ergo/pull/552), [#556](https://github.com/arkadianet/ergo/pull/556) |
| API010 | API010 | fixed | [ergo-api](historical/reports/ergo-api.md) | [#512](https://github.com/arkadianet/ergo/pull/512) |
| API011 | API011 | fixed | [ergo-api](historical/reports/ergo-api.md) | [#499](https://github.com/arkadianet/ergo/pull/499) |
| API012 | API012 | fixed | [ergo-api](historical/reports/ergo-api.md) | [#499](https://github.com/arkadianet/ergo/pull/499) |
| ST001 | ST001 | fixed | [ergo-state](historical/reports/ergo-state.md) | [#501](https://github.com/arkadianet/ergo/pull/501) |
| ST002 | ST002 | fixed | [ergo-state](historical/reports/ergo-state.md) | [#501](https://github.com/arkadianet/ergo/pull/501) |
| ST011 | ST011 | already_fixed | [ergo-state](historical/reports/ergo-state.md) | — |
| ST003 | ST003 | fixed | [ergo-state](historical/reports/ergo-state.md) | [#501](https://github.com/arkadianet/ergo/pull/501) |
| ST004 | ST004 | fixed | [ergo-state](historical/reports/ergo-state.md) | [#501](https://github.com/arkadianet/ergo/pull/501) |
| ST005 | ST005 | fixed | [ergo-state](historical/reports/ergo-state.md) | [#509](https://github.com/arkadianet/ergo/pull/509) |
| ST006 | ST006 | already_fixed | [ergo-state](historical/reports/ergo-state.md) | — |
| ST008 | ST008 | fixed | [ergo-state](historical/reports/ergo-state.md) | [#509](https://github.com/arkadianet/ergo/pull/509) |
| ST009 | ST009 | fixed | [ergo-state](historical/reports/ergo-state.md) | [#541](https://github.com/arkadianet/ergo/pull/541), [#561](https://github.com/arkadianet/ergo/pull/561), [#570](https://github.com/arkadianet/ergo/pull/570) |
| ST007 | ST007 | fixed | [ergo-state](historical/reports/ergo-state.md) | [#541](https://github.com/arkadianet/ergo/pull/541), [#561](https://github.com/arkadianet/ergo/pull/561) |
| ST010 | ST010 | fixed | [ergo-state](historical/reports/ergo-state.md) | [#541](https://github.com/arkadianet/ergo/pull/541) |
| SIG001 | SIG001 | fixed | [ergo-sigma](historical/reports/ergo-sigma.md) | [#498](https://github.com/arkadianet/ergo/pull/498), [#506](https://github.com/arkadianet/ergo/pull/506) |
| SIG002 | SIG002 | fixed | [ergo-sigma](historical/reports/ergo-sigma.md) | [#498](https://github.com/arkadianet/ergo/pull/498) |
| SIG003 | SIG003 | fixed | [ergo-sigma](historical/reports/ergo-sigma.md) | [#498](https://github.com/arkadianet/ergo/pull/498) |
| SIG004 | SIG004 | already_fixed | [ergo-sigma](historical/reports/ergo-sigma.md) | — |
| NODE001 | NODE001 | fixed | [ergo-node](historical/reports/ergo-node.md) | [#550](https://github.com/arkadianet/ergo/pull/550), [#555](https://github.com/arkadianet/ergo/pull/555) |
| NODE002 | NODE002 | already_fixed | [ergo-node](historical/reports/ergo-node.md) | — |
| NODE003 | NODE003 | fixed | [ergo-node](historical/reports/ergo-node.md) | [#538](https://github.com/arkadianet/ergo/pull/538) |
| NODE004 | NODE004 | fixed | [ergo-node](historical/reports/ergo-node.md) | [#535](https://github.com/arkadianet/ergo/pull/535) |
| NODE005 | NODE005 | fixed | [ergo-node](historical/reports/ergo-node.md) | [#525](https://github.com/arkadianet/ergo/pull/525) |
| NODE006 | NODE006 | fixed | [ergo-node](historical/reports/ergo-node.md) | [#537](https://github.com/arkadianet/ergo/pull/537) |
| NODE007 | NODE007 | fixed | [ergo-node](historical/reports/ergo-node.md) | [#539](https://github.com/arkadianet/ergo/pull/539) |
| NODE008 | NODE008 | fixed | [ergo-node](historical/reports/ergo-node.md) | [#532](https://github.com/arkadianet/ergo/pull/532), [#572](https://github.com/arkadianet/ergo/pull/572) |
| NODE009 | NODE009 | fixed | [ergo-node](historical/reports/ergo-node.md) | [#536](https://github.com/arkadianet/ergo/pull/536) |
| NODE010 | NODE010 | fixed | [ergo-node](historical/reports/ergo-node.md) | [#515](https://github.com/arkadianet/ergo/pull/515) |
| NODE011 | NODE011 | already_fixed | [ergo-node](historical/reports/ergo-node.md) | — |
| NODE012 | NODE012 | fixed | [ergo-node](historical/reports/ergo-node.md) | [#512](https://github.com/arkadianet/ergo/pull/512) |
| EC001 | EC001 | fixed | [ergo-compiler](historical/reports/ergo-compiler.md) | [#516](https://github.com/arkadianet/ergo/pull/516) |
| EC002 | ES010 | fixed | [ergo-compiler](historical/reports/ergo-compiler.md) | [#516](https://github.com/arkadianet/ergo/pull/516) |
| EC003 | EC003 | fixed | [ergo-compiler](historical/reports/ergo-compiler.md) | [#516](https://github.com/arkadianet/ergo/pull/516) |
| EC004 | EC004 | fixed | [ergo-compiler](historical/reports/ergo-compiler.md) | [#516](https://github.com/arkadianet/ergo/pull/516) |
| EC005 | EC005 | fixed | [ergo-compiler](historical/reports/ergo-compiler.md) | [#516](https://github.com/arkadianet/ergo/pull/516) |
| EC006 | EC006 | already_fixed | [ergo-compiler](historical/reports/ergo-compiler.md) | — |
| EC007 | EC007 | fixed | [ergo-compiler](historical/reports/ergo-compiler.md) | [#516](https://github.com/arkadianet/ergo/pull/516) |
| EV001 | EV001 | fixed | [ergo-validation](historical/reports/ergo-validation.md) | [#511](https://github.com/arkadianet/ergo/pull/511) |
| EV002 | EV002 | fixed | [ergo-validation](historical/reports/ergo-validation.md) | [#511](https://github.com/arkadianet/ergo/pull/511) |
| EV003 | EV003 | fixed | [ergo-validation](historical/reports/ergo-validation.md) | [#557](https://github.com/arkadianet/ergo/pull/557) |
| EV004 | EV004 | fixed | [ergo-validation](historical/reports/ergo-validation.md) | [#557](https://github.com/arkadianet/ergo/pull/557) |
| EV005 | ECSP003 | fixed | [ergo-validation](historical/reports/ergo-validation.md) | [#517](https://github.com/arkadianet/ergo/pull/517) |
| EV006 | EV006 | fixed | [ergo-validation](historical/reports/ergo-validation.md) | [#553](https://github.com/arkadianet/ergo/pull/553), [#554](https://github.com/arkadianet/ergo/pull/554) |
| EV007 | EV007 | already_fixed | [ergo-validation](historical/reports/ergo-validation.md) | — |
| EV008 | EV008 | fixed | [ergo-validation](historical/reports/ergo-validation.md) | [#557](https://github.com/arkadianet/ergo/pull/557) |
| WALLET001 | WALLET001 | fixed | [ergo-wallet](historical/reports/ergo-wallet.md) | [#502](https://github.com/arkadianet/ergo/pull/502) |
| WALLET002 | WALLET002 | fixed | [ergo-wallet](historical/reports/ergo-wallet.md) | [#502](https://github.com/arkadianet/ergo/pull/502) |
| WALLET003 | WALLET003 | already_fixed | [ergo-wallet](historical/reports/ergo-wallet.md) | — |
| WALLET004 | WALLET004 | already_fixed | [ergo-wallet](historical/reports/ergo-wallet.md) | — |
| WALLET005 | WALLET005 | fixed | [ergo-wallet](historical/reports/ergo-wallet.md) | [#534](https://github.com/arkadianet/ergo/pull/534) |
| WALLET006 | WALLET006 | fixed | [ergo-wallet](historical/reports/ergo-wallet.md) | [#533](https://github.com/arkadianet/ergo/pull/533) |
| WALLET007 | WALLET007 | fixed | [ergo-wallet](historical/reports/ergo-wallet.md) | [#525](https://github.com/arkadianet/ergo/pull/525) |
| WALLET008 | WALLET008 | fixed | [ergo-wallet](historical/reports/ergo-wallet.md) | [#527](https://github.com/arkadianet/ergo/pull/527) |
| WALLET009 | WALLET009 | already_fixed | [ergo-wallet](historical/reports/ergo-wallet.md) | — |
| EP2P001 | EP2P001 | already_fixed | [ergo-p2p](historical/reports/ergo-p2p.md) | — |
| EP2P002 | EP2P002 | fixed | [ergo-p2p](historical/reports/ergo-p2p.md) | [#528](https://github.com/arkadianet/ergo/pull/528) |
| EP2P003 | EP2P003 | already_fixed | [ergo-p2p](historical/reports/ergo-p2p.md) | — |
| EP2P004 | EP2P004 | fixed | [ergo-p2p](historical/reports/ergo-p2p.md) | [#528](https://github.com/arkadianet/ergo/pull/528) |
| EP2P005 | EP2P005 | fixed | [ergo-p2p](historical/reports/ergo-p2p.md) | [#528](https://github.com/arkadianet/ergo/pull/528) |
| EP2P006 | EP2P006 | fixed | [ergo-p2p](historical/reports/ergo-p2p.md) | [#528](https://github.com/arkadianet/ergo/pull/528) |
| EP2P007 | EP2P007 | fixed | [ergo-p2p](historical/reports/ergo-p2p.md) | [#528](https://github.com/arkadianet/ergo/pull/528) |
| EP2P008 | EP2P008 | fixed | [ergo-p2p](historical/reports/ergo-p2p.md) | [#529](https://github.com/arkadianet/ergo/pull/529) |
| EP2P009 | EP2P009 | fixed | [ergo-p2p](historical/reports/ergo-p2p.md) | [#528](https://github.com/arkadianet/ergo/pull/528) |
| EP2P010 | EP2P010 | fixed | [ergo-p2p](historical/reports/ergo-p2p.md) | [#528](https://github.com/arkadianet/ergo/pull/528) |
| ESY001 | ESY001 | fixed | [ergo-sync](historical/reports/ergo-sync.md) | [#559](https://github.com/arkadianet/ergo/pull/559) |
| ESY002 | ESY002 | fixed | [ergo-sync](historical/reports/ergo-sync.md) | [#559](https://github.com/arkadianet/ergo/pull/559), [#560](https://github.com/arkadianet/ergo/pull/560) |
| ESY003 | ESY003 | fixed | [ergo-sync](historical/reports/ergo-sync.md) | [#559](https://github.com/arkadianet/ergo/pull/559), [#565](https://github.com/arkadianet/ergo/pull/565) |
| ESY004 | ESY004 | fixed | [ergo-sync](historical/reports/ergo-sync.md) | [#559](https://github.com/arkadianet/ergo/pull/559) |
| ESY005 | ESY005 | fixed | [ergo-sync](historical/reports/ergo-sync.md) | [#559](https://github.com/arkadianet/ergo/pull/559) |
| ESY006 | ESY006 | fixed | [ergo-sync](historical/reports/ergo-sync.md) | [#559](https://github.com/arkadianet/ergo/pull/559) |
| ESY007 | ESY007 | fixed | [ergo-sync](historical/reports/ergo-sync.md) | [#559](https://github.com/arkadianet/ergo/pull/559) |
| ESY008 | ESY008 | fixed | [ergo-sync](historical/reports/ergo-sync.md) | [#559](https://github.com/arkadianet/ergo/pull/559) |
| ESY009 | ESY009 | fixed | [ergo-sync](historical/reports/ergo-sync.md) | [#559](https://github.com/arkadianet/ergo/pull/559) |
| MP001 | MP001 | fixed | [ergo-mempool](historical/reports/ergo-mempool.md) | [#513](https://github.com/arkadianet/ergo/pull/513) |
| MP002 | MP002 | fixed | [ergo-mempool](historical/reports/ergo-mempool.md) | [#520](https://github.com/arkadianet/ergo/pull/520) |
| MP003 | MP003 | fixed | [ergo-mempool](historical/reports/ergo-mempool.md) | [#519](https://github.com/arkadianet/ergo/pull/519) |
| MP004 | MP004 | fixed | [ergo-mempool](historical/reports/ergo-mempool.md) | [#519](https://github.com/arkadianet/ergo/pull/519) |
| MP005 | MP005 | fixed | [ergo-mempool](historical/reports/ergo-mempool.md) | [#513](https://github.com/arkadianet/ergo/pull/513), [#521](https://github.com/arkadianet/ergo/pull/521) |
| MP006 | MP006 | fixed | [ergo-mempool](historical/reports/ergo-mempool.md) | [#521](https://github.com/arkadianet/ergo/pull/521) |
| MP007 | MP007 | already_fixed | [ergo-mempool](historical/reports/ergo-mempool.md) | — |
| MP008 | MP008 | fixed | [ergo-mempool](historical/reports/ergo-mempool.md) | [#521](https://github.com/arkadianet/ergo/pull/521) |
| EM001 | EM001 | fixed | [ergo-mining](historical/reports/ergo-mining.md) | [#542](https://github.com/arkadianet/ergo/pull/542) |
| EM002 | EM002 | fixed | [ergo-mining](historical/reports/ergo-mining.md) | [#542](https://github.com/arkadianet/ergo/pull/542) |
| EM003 | EM003 | already_fixed | [ergo-mining](historical/reports/ergo-mining.md) | — |
| EM004 | EM004 | fixed | [ergo-mining](historical/reports/ergo-mining.md) | [#542](https://github.com/arkadianet/ergo/pull/542) |
| INDEXER001 | INDEXER001 | fixed | [ergo-indexer](historical/reports/ergo-indexer.md) | [#526](https://github.com/arkadianet/ergo/pull/526) |
| INDEXER002 | INDEXER002 | fixed | [ergo-indexer](historical/reports/ergo-indexer.md) | [#526](https://github.com/arkadianet/ergo/pull/526) |
| INDEXER003 | INDEXER003 | fixed | [ergo-indexer](historical/reports/ergo-indexer.md) | [#546](https://github.com/arkadianet/ergo/pull/546) |
| INDEXER004 | INDEXER004 | fixed | [ergo-indexer](historical/reports/ergo-indexer.md) | [#546](https://github.com/arkadianet/ergo/pull/546), [#567](https://github.com/arkadianet/ergo/pull/567), [#569](https://github.com/arkadianet/ergo/pull/569) |
| INDEXER005 | INDEXER005 | already_fixed | [ergo-indexer](historical/reports/ergo-indexer.md) | — |
| INDEXER006 | INDEXER006 | already_fixed | [ergo-indexer](historical/reports/ergo-indexer.md) | — |
| INDEXER007 | INDEXER007 | fixed | [ergo-indexer](historical/reports/ergo-indexer.md) | [#544](https://github.com/arkadianet/ergo/pull/544) |
| INDEXER008 | INDEXER008 | fixed | [ergo-indexer](historical/reports/ergo-indexer.md) | [#544](https://github.com/arkadianet/ergo/pull/544), [#566](https://github.com/arkadianet/ergo/pull/566) |
| INDEXER009 | INDEXER009 | fixed | [ergo-indexer](historical/reports/ergo-indexer.md) | [#545](https://github.com/arkadianet/ergo/pull/545) |
| INDEXER010 | INDEXER010 | already_fixed | [ergo-indexer](historical/reports/ergo-indexer.md) | — |
| ECR001 | ECR001 | fixed | [ergo-crypto](historical/reports/ergo-crypto.md) | [#530](https://github.com/arkadianet/ergo/pull/530) |
| ECR002 | ECR002 | fixed | [ergo-crypto](historical/reports/ergo-crypto.md) | [#514](https://github.com/arkadianet/ergo/pull/514) |
| ECR003 | ECR003 | fixed | [ergo-crypto](historical/reports/ergo-crypto.md) | [#514](https://github.com/arkadianet/ergo/pull/514) |
| ECR004 | ECR004 | fixed | [ergo-crypto](historical/reports/ergo-crypto.md) | [#514](https://github.com/arkadianet/ergo/pull/514) |
| TYPES001 | TYPES001 | fixed | [ergo-indexer-types](historical/reports/ergo-indexer-types.md) | [#547](https://github.com/arkadianet/ergo/pull/547) |
| REST001 | REST001 | fixed | [ergo-rest-json](historical/reports/ergo-rest-json.md) | [#522](https://github.com/arkadianet/ergo/pull/522) |
| REST002 | REST002 | fixed | [ergo-rest-json](historical/reports/ergo-rest-json.md) | [#522](https://github.com/arkadianet/ergo/pull/522) |
| REST003 | REST003 | fixed | [ergo-rest-json](historical/reports/ergo-rest-json.md) | [#523](https://github.com/arkadianet/ergo/pull/523) |
| REST004 | REST004 | fixed | [ergo-rest-json](historical/reports/ergo-rest-json.md) | [#523](https://github.com/arkadianet/ergo/pull/523) |
| REST005 | REST005 | already_fixed | [ergo-rest-json](historical/reports/ergo-rest-json.md) | — |
| EFF001 | EFF001 | remaining_evidence | [ergo-difftest-fuzz](historical/reports/ergo-difftest-fuzz.md) | — |
| EFF002 | EFF002 | remaining_evidence | [ergo-difftest-fuzz](historical/reports/ergo-difftest-fuzz.md) | [#568](https://github.com/arkadianet/ergo/pull/568) |
| EFF003 | EFF003 | fixed | [ergo-difftest-fuzz](historical/reports/ergo-difftest-fuzz.md) | [#568](https://github.com/arkadianet/ergo/pull/568) |
| WS001 | WS001 | already_fixed | [workspace](historical/reports/workspace.md) | — |
| WS002 | WS002 | already_fixed | [workspace](historical/reports/workspace.md) | — |
| WS003 | WS003 | fixed | [workspace](historical/reports/workspace.md) | [#503](https://github.com/arkadianet/ergo/pull/503) |
| WS004 | WS004 | fixed | [workspace](historical/reports/workspace.md) | [#507](https://github.com/arkadianet/ergo/pull/507) |
| WS005 | WS005 | fixed | [workspace](historical/reports/workspace.md) | [#507](https://github.com/arkadianet/ergo/pull/507) |
| WS006 | WS006 | fixed | [workspace](historical/reports/workspace.md) | [#508](https://github.com/arkadianet/ergo/pull/508) |

## Evidence scope and reproduction

[findings-map.json](findings-map.json) preserves every original ID and heading, the full owner row, shared-cause membership, all registry PRs, exact receipt fields and upstream source/fix SHAs resolved against the implementation base. The archived owner snapshots retain normalized wallet tree-equality qualifications and state/REST/indexer gates executed on cumulative heads; those gates are not relabeled as executions of a different focused head.

[manifest.json](manifest.json) hashes exact prompt copies, all 21 historical reports, owner snapshots and compact receipt copies. Larger coverage ledgers are inventoried with hashes and status-occurrence summaries; three compact historical ledgers are retained. Historical FULL_READ/PARTIAL_READ/HASH_ONLY claims apply only to their recorded audit hashes. No cache, JAR, build tree or large corpus is archived.

Historical reports retain their original bytes and references. Some old links point to session artifacts outside this compact archive; the manifest and evidence catalog identify the retained files without inventing missing evidence.

Verify the frozen copies and regenerate the index/map offline:

```sh
python3 scripts/reference-review-record.py --check
python3 scripts/reference-review-record.py
```

Refresh from the local live session after owners freeze their final dispositions:

```sh
python3 scripts/reference-review-record.py --refresh-source /path/to/original-checkout --control /path/to/audit/remediation/20261004-audit
```

Refreshing records a new timestamp and input hashes. It does not run native gates or resolve outstanding evidence. Include final integrated gates or strict cost receipts with repeated `--additional-receipt relative/path.json` arguments, relative to the control directory; the manifest lists those selections. Absent receipts remain absent.
