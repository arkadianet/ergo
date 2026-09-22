#!/usr/bin/env python3
"""Regenerate test-vectors/weak-blocks/*.json from the pinned Scala oracle.

Generation is SEEDED and therefore reproducible: regenerating at the
same ergo commit produces byte-identical payloads, so a vector diff
means upstream moved and nothing else. Without that, every regeneration
rewrote the `input_block_validation` fixtures (their chain's timestamps
came from the wall clock) and a re-pin could not be told from a re-run.

The COMMITTED manifest block carries only what identifies the inputs:
the commits, the generator hash and the seed. It used to carry this
run's wall-clock timestamp too, which meant no regeneration was ever
byte-identical and a re-pin could not be told from a re-run by reading
the diff. The timestamp is provenance, not payload, and now goes to an
untracked `provenance-<name>.json` beside the generator.
"""
import argparse
import datetime
import hashlib
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
# The provisioned build may live in a sibling worktree (provisioning is
# expensive and the pinned commits are the same), so the work directory
# is overridable. It is only ever READ.
WORK = Path(os.environ.get('WEAK_BLOCKS_ORACLE_WORK', str(HERE / '.work')))
OUT = ROOT / 'test-vectors/weak-blocks'
# Every name here must have a dispatch case in WeakBlocksOracle.main: an
# unknown name makes the oracle exit non-zero, and `check=True` then aborts
# the whole run, so a stale name silently starves every later vector.
VECTORS = ['announcement', 'ordering_announcement', 'messages', 'weak_ids', 'pow', 'extension_leaf', 'extension_proof', 'soft_fields', 'input_block_validation', 'block_sections', 'launch_params']


# The fixture generator's base timestamp. FIXED, and changed only
# deliberately: changing it rewrites every `input_block_validation`
# fixture (and nothing else), which is a vector diff a reader has to be
# able to attribute.
DEFAULT_SEED = 1600000000000

# Where this run's wall-clock provenance goes. NOT inside the build's
# work directory: a provisioned build is immutable while a devnet runs
# out of it (spec §7a), and this file is written on every regeneration.
# The `.work*` glob beside the generator is already gitignored, which is
# what keeps the timestamp out of the committed vectors.
PROVENANCE = HERE / '.work-provenance'


def vector_manifest(manifest, oracle_sha256, seed):
    """The `manifest` block a COMMITTED vector carries.

    Every field identifies an INPUT — the two commits, the sigma
    version, the generator and its hash, the seed. Nothing here varies
    between two runs at the same pin, which is what makes regeneration
    byte-identical and a vector diff attributable to upstream.
    """
    return {
        'ergo_commit': manifest['ergo_commit'],
        'sigma_commit': manifest['sigma_commit'],
        'sigma_version': manifest['sigma_version'],
        'generator': 'scripts/jvm_weak_blocks_oracle/WeakBlocksOracle.scala',
        'generator_sha256': oracle_sha256,
        'seed': seed,
    }


def provenance_record(name, manifest, oracle_sha256, seed, when=None):
    """When THIS run generated `name`, and from which work directory.

    Kept beside the generator rather than in the vector: it answers "when
    was this last regenerated", which is a fact about the run, and
    putting it in the payload made every regeneration a diff.
    """
    record = vector_manifest(manifest, oracle_sha256, seed)
    record['vector'] = name
    record['work_dir'] = str(WORK)
    record['generated_at'] = (
        when or datetime.datetime.now(datetime.timezone.utc)).isoformat()
    return record


def write_provenance(name, record):
    PROVENANCE.mkdir(parents=True, exist_ok=True)
    path = PROVENANCE / f'provenance-{name}.json'
    path.write_text(json.dumps(record, indent=2) + '\n')
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('vectors', nargs='*', default=None,
                        help=f'which to regenerate; default all of {VECTORS}')
    parser.add_argument('--seed', type=int, default=DEFAULT_SEED,
                        help='base timestamp for generated fixture blocks; '
                             f'default {DEFAULT_SEED}. Changing it changes '
                             'the fixture bytes, so it is part of the vectors')
    parser.add_argument('--self-test', action='store_true',
                        help='check that a committed vector carries no '
                             'wall clock, and generate nothing')
    args = parser.parse_args()
    if args.self_test:
        _self_test()
        return
    names = args.vectors or VECTORS
    manifest = json.loads((WORK / 'manifest.json').read_text())
    oracle = HERE / 'WeakBlocksOracle.scala'
    OUT.mkdir(parents=True, exist_ok=True)
    for name in names:
        # ONE oracle source, so ONE classpath: `WeakBlocksOracle.scala` is a
        # single compilation unit and `input_block_validation` pulls in ergo's
        # Test-scope helpers, which means the whole file only compiles against
        # `.work/test-classpath`. That classpath is a superset of the Runtime
        # one, so every subcommand runs on it. `.work/classpath` is still
        # exported by provision.py as the Runtime-scope record and for the
        # README's smoke test, but no vector is generated from it.
        classpath = (WORK / 'test-classpath').read_text().strip()
        # The Test-scope helpers read `src/test/resources/application.conf` by a
        # RELATIVE path (`ErgoNodeTestConstants.initSettings`), so the JVM's
        # working directory has to be the pinned ergo checkout for the vectors
        # that touch them.
        cwd = str(WORK / 'source') if name == 'input_block_validation' else None
        # `block_sections` reads this repo's mainnet fixtures, so it is handed
        # the worktree root explicitly rather than inheriting a working
        # directory (which the line above may override per vector).
        extra = [str(ROOT)] if name == 'block_sections' else []
        result = subprocess.run(['scala-cli', '--skip-cli-updates', 'run', str(oracle), '--server=false',
                                 '--scala', '2.12.20', '--classpath', classpath, '--', name, *extra,
                                 '--seed', str(args.seed)],
                                text=True, stdout=subprocess.PIPE, check=True, cwd=cwd).stdout
        # logback initialization banner (and scala-cli's outdated-version nag) land on
        # stdout ahead of the JSON payload, and can themselves contain '{' (log pattern
        # strings), so anchor on the line that is exactly the JSON object's opening
        # brace rather than the first '{' anywhere in the output.
        lines = result.splitlines()
        # Anchor on an UNINDENTED lone '{' (the payload is printed with
        # `Json.spaces2`, so only its outer brace sits at column 0) and take the
        # LAST one: test-scope vectors log a pretty-printed ErgoLikeContext on
        # stdout ahead of the payload, whose nested braces would otherwise match.
        json_start = max(i for i, line in enumerate(lines) if line == '{')
        doc = json.loads('\n'.join(lines[json_start:]))
        oracle_sha = hashlib.sha256(oracle.read_bytes()).hexdigest()
        doc['manifest'] = vector_manifest(manifest, oracle_sha, args.seed)
        (OUT / f'{name}.json').write_text(json.dumps(doc, indent=2) + '\n')
        # The wall clock lives HERE, untracked, so regenerating at the
        # same pin leaves the committed vector byte-identical.
        where = write_provenance(name, provenance_record(
            name, manifest, oracle_sha, args.seed))
        print(f'wrote {name}.json ({len(doc.get("cases", []))} cases); '
              f'provenance {where}')


def _self_test():
    """The committed payload may not vary between two runs at one pin."""
    pin = {'ergo_commit': '62c10315', 'sigma_commit': '368a860b',
           'sigma_version': '6.0.5-22-368a860b-SNAPSHOT'}
    first = vector_manifest(pin, 'deadbeef', DEFAULT_SEED)
    second = vector_manifest(pin, 'deadbeef', DEFAULT_SEED)
    assert first == second, (first, second)
    assert json.dumps(first, indent=2) == json.dumps(second, indent=2)
    # The wall clock is the one field that cannot be in there.
    assert 'timestamp' not in first and 'generated_at' not in first, first
    assert not any('time' in key for key in first), first
    # Every field names an INPUT, so a diff is attributable to upstream.
    assert set(first) == {'ergo_commit', 'sigma_commit', 'sigma_version',
                          'generator', 'generator_sha256', 'seed'}, first
    # A different seed, commit or generator IS a different vector.
    assert vector_manifest(pin, 'deadbeef', DEFAULT_SEED + 1) != first
    assert vector_manifest(pin, 'cafe', DEFAULT_SEED) != first
    assert vector_manifest({**pin, 'ergo_commit': 'other'},
                           'deadbeef', DEFAULT_SEED) != first
    # And the provenance record keeps the timestamp, so "when was this
    # regenerated" is still answerable — just not from the payload.
    when = datetime.datetime(2026, 9, 23, tzinfo=datetime.timezone.utc)
    record = provenance_record('pow', pin, 'deadbeef', DEFAULT_SEED, when)
    assert record['generated_at'] == when.isoformat(), record
    assert record['vector'] == 'pow', record
    assert {k: record[k] for k in first} == first, record
    print('gen self-test OK: the committed manifest carries no wall clock')


if __name__ == '__main__':
    main()
