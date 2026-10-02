# Releasing binaries

The release workflow resolves a `vMAJOR.MINOR.PATCH` tag (or prerelease tag) to
one commit and checks that its version matches `[workspace.package].version`.
Reusable CI and the cost ledger validate that exact commit before any build or
publication. Failed, cancelled or skipped prerequisite jobs block publication.

Every platform builds with `--locked`, packages the binaries, configuration
templates and operating docs, then runs the extracted binaries' `--help` and
`--version`. The node also boots a fresh temporary devnet database, serves
`/info`, shuts down through its authenticated API, reopens the same database and
shuts down again. Devnet has no public seed peers; smoke peers and HTTP requests
use loopback, peer enrichment is disabled, and temporary credentials/state are
removed afterward. Linux glibc, Linux musl, macOS and Windows run this check on
their native runners. A smoke timeout fails the build and prevents upload.

Archives contain `config/ergo-node.toml`, the commented example, a binary
quickstart, configuration/operating/compatibility/logging docs and licenses.
Checksums cover each binary and archive. A per-platform JSON manifest records
the source commit, workspace version and checksums. The publishing job uses
that same commit and rejects a tag that has moved or disappeared from origin.
Do not retarget published release tags.

To cut a release, update the workspace version and changelog, merge the change,
and push its matching tag. A manual run accepts the same tag; it does not bypass
validation. Tool versions are in `rust-toolchain.toml` (stable compiler) and
`.github/ci-tools.toml` (auditors, nextest and the tested fuzz nightly).
Dependabot proposes Cargo and immutable GitHub Action pin updates. Review tool
version changes and rerun the gates before committing them.

Local helper validation requires Python 3.11 or later:

```sh
python3 scripts/ci-policy.py
python3 -m unittest discover -s scripts -p 'test_release*.py'
cargo build --locked --release --bin ergo-node --bin ergo-wallet
python3 scripts/release.py package --target x86_64-unknown-linux-gnu \
  --binaries target/release --output target/release-smoke
```

Choose the matching supported target on macOS/Windows, including `.exe`
binaries. Debug binaries can be supplied for a quicker local smoke; production
archives always use release builds. These local checks exercise helper behavior
and booting on the current host. Cross-platform build, execution and GitHub
publication are verified by the release workflow, not inferred from a local
Linux result.
