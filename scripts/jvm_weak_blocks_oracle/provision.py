#!/usr/bin/env python3
"""Build a pinned Scala weak-blocks node + its sigma-state fork snapshot
into an isolated classpath.

M4 measures one patch at a time, so this is parametrised: the source may
be the upstream repository or the local fork checkout, the ref may be a
commit or a patch branch, and each build gets its own work directory
(`scripts/devnet-matrix/builds.toml` is the list of them). Three rules
come from spec §7a and are not negotiable:

* **Artifacts are immutable while a devnet runs.** A LOCAL source is
  `git worktree`-ed at the ref rather than checked out and cleaned:
  `git clean -fdx` would delete the compiled output of a build another
  run may be using, and would throw away the incremental state that
  makes a patch cycle two minutes instead of fifteen.
* **Sigma is provisioned once.** `--sigma-reuse` skips `publishLocal`
  when the jars already in `~/.ivy2/local` hash the same as the ones a
  recorded manifest was built against. It does not skip on the hope that
  a jar with the right NAME is the right jar.
* **Build identity is the compiled output.** `class_dir_sha256` in the
  manifest is the sha256 of every class file on the exported runtime
  classpath, so a role can refuse a build that has moved under it.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
DEFAULT_WORK = HERE / '.work'
# The M4 pin (spec §2): upstream master merged after 6.0.6. Every vector
# and every devnet number in this milestone is against this commit.
ERGO_REPO = 'https://github.com/ergoplatform/ergo.git'
ERGO_COMMIT = '62c10315e1ebcac4480dba6bacdc2100a38119e5'
SIGMA_REPO = 'https://github.com/ScorexFoundation/sigmastate-interpreter.git'
SIGMA_COMMIT = '368a860be033af94aa14895381f42099b3646db6'
SIGMA_VERSION = '6.0.5-22-368a860b-SNAPSHOT'
IVY_LOCAL = Path.home() / '.ivy2/local/org.scorexfoundation'

# The build-identity hash lives with the registry that CHECKS it: a
# manifest written by one algorithm and verified by another would fail
# every verification for a build that is perfectly fine.
sys.path.insert(0, str(ROOT / 'scripts/devnet-matrix'))
from builds import app_version_of, class_dir_sha256  # noqa: E402


def run(cmd, cwd, log):
    with log.open('a') as out:
        out.write('$ ' + ' '.join(cmd) + '\n')
        subprocess.run(cmd, cwd=cwd, stdout=out, stderr=subprocess.STDOUT, check=True)


def git(args, cwd):
    return subprocess.run(['git', *args], cwd=cwd, capture_output=True,
                          text=True, check=True).stdout.strip()


def clone_checkout(url, ref, dest, log):
    """A REMOTE source: clone once, then hard-reset onto the ref.

    No `git clean`: the work directory is this build's alone, and its
    untracked content is the compiled output that makes the next cycle
    incremental. Tracked files are still asserted clean, which is what
    "the pinned ref is what got built" actually requires.
    """
    if not (dest / '.git').exists():
        run(['git', 'clone', '--filter=blob:none', url, str(dest)], HERE, log)
    run(['git', 'fetch', 'origin', ref], dest, log)
    run(['git', 'checkout', '--detach', 'FETCH_HEAD'], dest, log)
    run(['git', 'reset', '--hard', 'FETCH_HEAD'], dest, log)
    status = git(['status', '--porcelain', '--untracked-files=no'], dest)
    assert status == '', f'{dest} has modified tracked files at {ref}:\n{status}'
    return git(['rev-parse', 'HEAD'], dest)


def worktree_checkout(source, ref, dest, log):
    """A LOCAL source: a detached `git worktree` at the ref.

    A worktree rather than a second clone because the fork's branches
    are all in the one checkout, and rather than a checkout IN that
    directory because another session's work lives there (see the plan's
    global constraints). Never cleaned, for the reasons in the module
    docstring.
    """
    source = Path(source).resolve()
    if not (source / '.git').exists():
        raise SystemExit(f'{source} is not a git checkout')
    if (dest / '.git').exists():
        # Already a worktree of this source: move it to the ref in
        # place, keeping the compiled output beside it.
        run(['git', 'checkout', '--detach', ref], dest, log)
    else:
        dest.parent.mkdir(parents=True, exist_ok=True)
        # `--force` only defeats the "already checked out elsewhere"
        # guard, which is exactly the case here: the ref may be the
        # branch the source checkout itself has open.
        run(['git', 'worktree', 'add', '--detach', '--force', str(dest), ref],
            source, log)
    status = git(['status', '--porcelain', '--untracked-files=no'], dest)
    assert status == '', f'{dest} has modified tracked files at {ref}:\n{status}'
    return git(['rev-parse', 'HEAD'], dest)


def checkout(source, ref, dest, log):
    local = Path(os.path.expanduser(source))
    if local.exists() and local.is_dir():
        return worktree_checkout(local, ref, dest, log)
    return clone_checkout(source, ref, dest, log)


def export_classpath(source, config, work, log):
    # `run` APPENDS, so a marker left by an earlier provision run would still
    # hold that run's classpath line. Truncate it first: otherwise an sbt
    # export that succeeds without emitting a classpath (a changed build, a
    # different sbt) lets the reverse search silently return a stale path.
    marker = work / f'{config.lower()}-classpath.log'
    marker.unlink(missing_ok=True)
    run(['sbt', '-batch', f'export {config} / fullClasspath'], source, marker)
    lines = marker.read_text().splitlines()
    matches = [line for line in lines if line.startswith('/') and 'scala-library' in line]
    if not matches:
        raise RuntimeError(f'{config} / fullClasspath export produced no classpath line; see {marker}')
    return matches[-1]


def sigma_jars():
    return sorted(p for p in IVY_LOCAL.glob(
        f'sigma-state_*/{SIGMA_VERSION}/jars/*.jar'))


def hash_jars(jars):
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in jars}


def recorded_sigma_artifacts(work):
    """Sigma jar hashes from an already-provisioned build, if any.

    Searched over the SIBLING work directories: a second build at the
    same sigma pin should reuse the jars the first one published, and
    the record of what those jars were is the first one's manifest.
    """
    for manifest_path in sorted(work.parent.glob('.work*/manifest.json')):
        try:
            manifest = json.loads(manifest_path.read_text())
        except (OSError, ValueError):
            continue
        if (manifest.get('sigma_commit') == SIGMA_COMMIT
                and manifest.get('sigma_version') == SIGMA_VERSION
                and manifest.get('sigma_artifacts')):
            return manifest['sigma_artifacts'], str(manifest_path)
    return None, None


def clear_outputs(work):
    """Remove this build's own outputs — AFTER its manifest has been read.

    Ordering, not housekeeping. `recorded_sigma_artifacts` searches every
    sibling work directory INCLUDING this one, so deleting
    `manifest.json` first threw away the only record of which sigma jars
    the jars on disk were published from, and `--sigma-reuse` then
    republished sigma for a build whose jars already matched.
    """
    for name in ('classpath', 'test-classpath', 'manifest.json'):
        (work / name).unlink(missing_ok=True)


def sigma_reuse_decision(reuse, jar_hashes, recorded, source=None):
    """`(take_the_reuse, why)` — the whole `--sigma-reuse` rule, pure.

    Reuse is taken only when the jars on disk hash EXACTLY the same as
    the ones a recorded manifest was built against: a jar with the right
    NAME is not evidence, and a silently different interpreter would
    change vector bytes with nothing to say it had.
    """
    if not reuse:
        return False, 'not asked for'
    if not jar_hashes:
        return False, 'no jars published'
    if not recorded:
        return False, 'no recorded manifest to compare against'
    if jar_hashes != recorded:
        return False, 'the published jars do not hash the same as the recorded ones'
    return True, f'reused; hashes match {source}'


def provision_sigma(work, log, reuse, recorded=None):
    """Publish the sigma fork snapshot locally, or prove it is already there.

    Returns `(jars, how)`. `recorded` is the `(hashes, source)` pair read
    BEFORE this build's own outputs were cleared; passing it is what
    makes a re-provision of the build that holds the only record still
    able to reuse its jars.
    """
    if reuse:
        jars = sigma_jars()
        if recorded is None:
            recorded = recorded_sigma_artifacts(work)
        hashes, source = recorded
        take, why = sigma_reuse_decision(reuse, hash_jars(jars) if jars else {},
                                         hashes, source)
        if take:
            return jars, why
        print(f'--sigma-reuse not taken: {why}; publishing')
    sigma = work / 'sigma'
    clone_checkout(SIGMA_REPO, SIGMA_COMMIT, sigma, log)
    # The ergo build pins this exact SNAPSHOT string; publish both Scala binaries it consumes.
    run(['sbt', '-batch', f'set ThisBuild / version := "{SIGMA_VERSION}"', '+publishLocal'], sigma, log)
    jars = sigma_jars()
    assert jars, f'no sigma-state jars published under {IVY_LOCAL}'
    return jars, 'published by this run'


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--ergo-source', default=ERGO_REPO,
                        help='a git URL (cloned) or a local checkout (a '
                             'detached worktree is added at the ref); '
                             f'default {ERGO_REPO}')
    parser.add_argument('--ergo-ref', default=ERGO_COMMIT,
                        help=f'commit, tag or branch; default {ERGO_COMMIT}')
    parser.add_argument('--work-dir', default=str(DEFAULT_WORK),
                        help='where this build lives; one per build, listed '
                             'in scripts/devnet-matrix/builds.toml')
    parser.add_argument('--sigma-reuse', action='store_true',
                        help='skip the sigma publishLocal when the jars in '
                             '~/.ivy2/local already hash the same as the ones '
                             'a recorded manifest was built against')
    parser.add_argument('--self-test', action='store_true',
                        help='check the reuse rule and the read-before-clear '
                             'ordering, and provision nothing')
    args = parser.parse_args(argv)
    if args.self_test:
        _self_test()
        return 0

    work = Path(os.path.expanduser(args.work_dir)).resolve()
    work.mkdir(parents=True, exist_ok=True)
    # READ BEFORE CLEARING. This build's own manifest is one of the
    # records `--sigma-reuse` compares against, and when it is the only
    # one, clearing it first made every re-provision republish sigma.
    recorded_sigma = recorded_sigma_artifacts(work)
    clear_outputs(work)
    log = work / 'provision.log'
    log.unlink(missing_ok=True)

    jars, sigma_how = provision_sigma(work, log, args.sigma_reuse,
                                      recorded=recorded_sigma)

    ergo = work / 'source'
    commit = checkout(args.ergo_source, args.ergo_ref, ergo, log)
    # The sigma pin is hard-coded here and injected through
    # SIGMASTATE_VERSION. What the build itself asks for is RECORDED in
    # the manifest beside it, so a fork that moved its sigma dependency
    # is visible in the artifact rather than silently overridden — a
    # vector generated against the wrong interpreter is wrong in a way
    # nothing downstream can detect.
    declared = subprocess.run(
        ['grep', '-rho', r'sigmaStateVersion.*', str(ergo / 'build.sbt')],
        capture_output=True, text=True).stdout
    os.environ['SIGMASTATE_VERSION'] = SIGMA_VERSION
    runtime = export_classpath(ergo, 'Runtime', work, log)
    test = export_classpath(ergo, 'Test', work, log)
    (work / 'classpath').write_text(runtime + '\n')
    (work / 'test-classpath').write_text(test + '\n')
    manifest = {
        'ergo_source': args.ergo_source,
        'ergo_ref': args.ergo_ref,
        'ergo_commit': commit,
        'sigma_commit': SIGMA_COMMIT,
        'sigma_version': SIGMA_VERSION,
        'sigma_provisioning': sigma_how,
        'sigma_version_declared_by_build': declared.strip().splitlines()[:2],
        'sigma_artifacts': hash_jars(jars),
        'app_version': app_version_of(ergo),
        # The build's IDENTITY: what a devnet role verifies before it
        # will run this build (spec §7a).
        'class_dir_sha256': class_dir_sha256(runtime),
    }
    (work / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(f'Provisioned ergo {commit[:8]} ({manifest["app_version"]}) '
          f'with sigma {SIGMA_VERSION} [{sigma_how}] in {work}')
    return 0


def _self_test():
    """The two decisions provisioning makes that can silently be wrong."""
    import tempfile

    # ----- the reuse rule -----
    same = {'sigma-state_2.12.jar': 'aa'}
    assert sigma_reuse_decision(False, same, same)[0] is False
    take, why = sigma_reuse_decision(True, same, same, 'x/manifest.json')
    assert take and 'hashes match x/manifest.json' in why, why
    assert sigma_reuse_decision(True, {}, same) == (
        False, 'no jars published')
    assert sigma_reuse_decision(True, same, None) == (
        False, 'no recorded manifest to compare against')
    # A jar with the right NAME and different bytes is not the same jar.
    assert sigma_reuse_decision(
        True, same, {'sigma-state_2.12.jar': 'bb'})[0] is False

    # ----- read before clear -----
    #
    # The failure this ordering exists for: a re-provision of the build
    # that holds the ONLY record of the published jars. Clearing first
    # loses it and sigma is republished for jars that already match.
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp) / '.work-probe'
        work.mkdir()
        (work / 'manifest.json').write_text(json.dumps({
            'sigma_commit': SIGMA_COMMIT, 'sigma_version': SIGMA_VERSION,
            'sigma_artifacts': same}) + '\n')
        recorded = recorded_sigma_artifacts(work)
        assert recorded[0] == same, recorded
        clear_outputs(work)
        assert recorded_sigma_artifacts(work) == (None, None), \
            'the only record is gone once the outputs are cleared'
        # Which is exactly why it is captured first: the decision made
        # with the captured record still reuses.
        assert sigma_reuse_decision(True, same, *recorded)[0] is True
        # And a build that never had one is not pretended to have.
        assert sigma_reuse_decision(
            True, same, *recorded_sigma_artifacts(work))[0] is False
    print('provision self-test OK: the sigma reuse rule and read-before-clear')


if __name__ == '__main__':
    raise SystemExit(main())
