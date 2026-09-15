# Historical L4 selection and replay

`mainnet-epochs.json.gz` records all 1,830 epoch extensions through mainnet height
1,873,956 from the 6.0.5 oracle node. It also contains headers immediately before
and at block-version activations: 417,792 (v2), 889,856 (v3 / Ergo 5.0), and
1,628,160 (v4 / Ergo 6.0). The runner parses these extensions through
`parse_active_params` and `ProtocolParams::from_active` at each transaction height.

`REQUIRED_RANGES` contains the ten stratified windows and each activation ±1024.
Changes to voted IDs 4–8 add a one-block range unless an existing required range
covers the change. There are 377 changed epochs and 388 required ranges in this
snapshot. Single-block voted-change ranges satisfy the “at least one range per
change” requirement; activation windows retain the complete ±1024 requirement.

Run Cargo commands serially. Paths in test environment variables are relative
to the `ergo-validation` crate; Python commands run from the worktree root.

```sh
# Refresh only when deliberately updating the pinned historical snapshot.
python3 test-vectors/scripts/extract_l4_epochs.py test-vectors/ergo-sigma/cost-total/mainnet-epochs.json.gz

L4_SELECTION=../target/l4-selection.json cargo test -p ergo-validation --features diagnostics --test it cost_parity::ranges::cost_parity_required_matrix_records_mainnet_selection
python3 test-vectors/scripts/extract_l4_selection.py target/l4-selection.json target/l4-extraction

L4_DIAGNOSTICS=../target/l4-diagnostics.json L4_RESULTS=../test-vectors/ergo-sigma/cost-ledger/results/l4-YYYY-MM-DD.json cargo test -p ergo-validation --features diagnostics --test it cost_parity::ranges::cost_parity_required_selection_matches_jvm -- --nocapture
python3 test-vectors/scripts/record_l4_provenance.py test-vectors/ergo-sigma/cost-ledger/results/l4-YYYY-MM-DD.json
```

The extractor runs one JVM, serially, and reloads epoch parameters plus the nine
ancestors at every gap. `--resume-fixture` splits a successfully completed
`COST_FIXTURE` without rerunning the oracle. Dedicated fixture JSON avoids JVM
messages interleaved with stdout. Large transaction/header/cost/box files are
ignored; tracked manifests carry hashes. Compact activation, checkpoint, and
divergence fixtures run or compile with the ordinary test suite.

For an older range missing external input boxes:

```sh
L4_RANGE=500000-501000 L4_DIAGNOSTICS=../target/l4-diagnostics.json cargo test -p ergo-validation --features diagnostics --test it cost_parity::ranges::cost_parity_required_selection_matches_jvm -- --nocapture
L4_DIAGNOSTICS=target/l4-diagnostics.json bash test-vectors/scripts/extract_input_boxes.sh 500000 501000 test-vectors/mainnet/input_boxes_500000_501000.json
```

`L4_RANGE` permits diagnostic subsets. `L4_RESULTS` refuses a subset or any
unexecuted required range. A fully executed run with real mismatches writes its
failed observations and then fails the test. `L4_DIAGNOSTICS` can also record
incomplete runs, with transaction IDs and missing-box IDs itemized. The harness
retains historical boxes for data inputs even after an in-block spend.

## Current divergence

The full snapshot executes 101,187 selected transactions with no skips and two
Rust rejections at heights 1,628,276 and 1,628,279. Both are independently accepted
by JVM `validateStateful`; their frozen expectations remain acceptance with costs
23,851 and 23,925. `l4-v6-reject-valid.json` retains both transactions, every needed
box, exact header contexts and parameters. The diagnostic test
`transaction_v6_activation_spends_match_jvm` fails until production parity is
restored. Ledger row `TX-l4-v6-activation-reject-valid` tracks the discrepancy.

The snapshot does not cover scripts absent from mainnet, later mainnet changes,
or behavior after the pinned Ergo 6.0.5 / sigma-state 6.0.6 oracle versions.
