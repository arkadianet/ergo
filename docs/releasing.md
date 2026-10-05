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

Each `ergo-<target>.tar.gz` archive (`.zip` on Windows) contains both programs
at its root, `config/ergo-node.toml`, the commented example, a binary quickstart,
operator docs, `deploy/` examples and licenses. Internal `release-info.json`
(schema version 1) records the tag, workspace version, source SHA, target and
executable SHA-256s. Archive metadata uses the source commit timestamp, fixed
gzip header time, sorted members, normalized ownership and file modes. This
makes packaging repeatable for identical supplied binaries and support files;
it does not promise reproducible Rust builds.

Each matrix job uploads one archive and a private `receipt-<target>.json` after
both extracted programs pass help/version checks and the node smoke passes.
The publishing job requires exactly six distinct target receipts with matching
tag/version/SHA and successful smoke results. It checks actual archive sizes,
archive and executable hashes, required contents and internal release metadata,
rejecting duplicate names, unsafe members, missing targets and unexpected files.

Only eight assets are published: the six combined archives, `release.json`
and `SHA256SUMS`. There are no bare binaries, per-file `.sha256` sidecars or
per-target public manifests, and no transition files. Release-wide `release.json`
(schema version 1) has `tag`, `version`, `sha` and a `targets` map. Each target
entry gives `archive`, `size` in bytes, `sha256` and `executables` keyed by name
with internal `sha256` values. `SHA256SUMS` has seven rows: the archives and
`release.json`, sorted by basename with exactly two spaces after each lowercase
hex digest and LF line endings. It never hashes itself. Manifest archive hashes
must match the checksum rows. See the [binary quickstart](release-quickstart.md)
for checking only the platform files you downloaded.

The publishing job uses the validated source commit and rejects a tag that
has moved or disappeared from origin, including a final check immediately before
publication. Do not retarget published release tags. Existing release downloads
are left intact; updaters using bare names must switch to the combined archive.
Reruns compare existing asset names, sizes and downloaded hashes before upload;
identical files are retained, missing files may be uploaded, and conflicting or
unexpected assets require a new tag or a maintainer recovery procedure.

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
python3 scripts/release.py aggregate --input target/release-smoke \
  --output target/release-public --tag "v$(python3 -c 'import tomllib; print(tomllib.load(open("Cargo.toml", "rb"))["workspace"]["package"]["version"])')" \
  --sha "$(git rev-parse HEAD)" --test-target x86_64-unknown-linux-gnu
```

Use empty output directories. `aggregate` normally requires all six targets;
`--test-target` is an explicit local fixture option and is never used in the
publishing workflow. `verify-assets --input DIR --tag TAG --sha SHA` independently
checks the final inventory and manifest/checksum agreement.

Choose the matching supported target on macOS/Windows, including `.exe`
binaries. Debug binaries can be supplied for a quicker local smoke; production
archives always use release builds. These local checks exercise helper behavior
and booting on the current host. Cross-platform build, execution and GitHub
publication are verified by the release workflow, not inferred from a local
Linux result.
