#!/usr/bin/env python3
"""The provisioned Scala Matrix builds a devnet role may run (spec §4, §7a).

M4 measures one patch at a time, so more than one Scala build has to be
on this host at once: the stock upstream pin, one work directory per
patch branch, and the integration build. `builds.toml` is the list, this
module is how a role gets one, and `Build.verify()` is what stops a role
running a build that is not what its manifest says it is.

Build identity is the COMPILED OUTPUT, not the source commit. The
harness launches the Scala node from exported class directories, so two
work directories at the same commit can still differ (a half-finished
`sbt compile`, a stale incremental cache, an edited file) and the commit
alone would not show it. `class_dir_sha256` hashes every class file on
the runtime classpath; a role whose build does not reproduce its
manifest's hash refuses to start, because a devnet number attributed to
the wrong build is worse than no number.

Legacy manifests (written before the hash existed) are tolerated but not
trusted quietly: the hash is computed on first use and cached in a
SIDECAR beside the work directory. Provisioned builds are immutable
while a devnet runs — nothing is ever written inside one.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
BUILDS_TOML = HERE / 'builds.toml'

# The names `campaign.py --build` / `--base-build` accept. Fixed here
# rather than taken from the file so a typo in `builds.toml` is an error
# rather than a new build nobody provisions. `base` is the #2563
# re-measure's base (weak-blocks @ a1bd938ef), `base+2506`, `2563f` and
# `2563f+2506` are its two arms, `2562f` is the #2562 two-miner
# reconstruction build, and `soak` is the integration build of every
# patch we filed.
BUILD_NAMES = ('stock', 'F16', 'F12F05', 'F14', 'F13', 'F04', 'F11', 'all',
               'base', 'base+2506', '2563f', '2563f+2506', '2562f', 'soak')

# A registry entry's `ergo_ref`: a full commit id, never a branch name,
# so a later branch move cannot change what a rerun provisions.
FULL_COMMIT = re.compile(r'[0-9a-f]{40}')

# A class directory as sbt's `export Runtime / fullClasspath` names it.
CLASSES_DIR = re.compile(r'/target/scala-[^/]+/classes/?$')


class BuildError(RuntimeError):
    """A build is missing, unreadable, or is not what its manifest says."""


def _classes_dirs(classpath):
    """The compiled-output directories on a classpath, in file order."""
    return [Path(entry) for entry in classpath.strip().split(os.pathsep)
            if entry and CLASSES_DIR.search(entry)]


def _project_of(classes_dir):
    """The sbt project a class directory belongs to.

    `<work>/source/ergo-core/target/scala-2.12/classes` -> `ergo-core`.
    Keyed by the project rather than the absolute path so the SAME
    compiled output hashes the same in two different work directories —
    which is the whole point of comparing builds by their output.
    """
    return classes_dir.parents[2].name


def class_dir_sha256(classpath):
    """Hash every compiled class on a runtime classpath.

    sha256 over the sorted `<project>/<relative path>` plus each file's
    own digest. Sorted because a directory walk is not ordered, and the
    path is folded in because moving a class between projects has to
    change the hash as much as changing its bytes does.

    `provision.py` imports THIS function rather than carrying its own
    copy: a manifest written by one algorithm and checked by another
    would fail every verification for a build that is perfectly fine.
    """
    dirs = _classes_dirs(classpath)
    if not dirs:
        raise BuildError(
            'no */target/scala-*/classes entry on the classpath; this is not '
            'an exported Runtime classpath of an ergo build')
    digest = hashlib.sha256()
    entries = []
    for classes in dirs:
        if not classes.is_dir():
            raise BuildError(f'classpath names {classes}, which does not exist')
        project = _project_of(classes)
        for path in classes.rglob('*'):
            if path.is_file():
                entries.append((f'{project}/{path.relative_to(classes)}', path))
    for key, path in sorted(entries):
        digest.update(key.encode())
        digest.update(b'\0')
        digest.update(hashlib.sha256(path.read_bytes()).digest())
        digest.update(b'\0')
    return digest.hexdigest()


def app_version_of(source_dir):
    """`org.ergoplatform.Version.VersionString` of a provisioned build.

    Read from the version file sbt GENERATES into `src_managed` rather
    than recomputed from `git describe`: it is the string the node will
    actually report on `/info.appVersion`, which is what `lifecycle`
    checks a launched node against.
    """
    source = Path(source_dir)
    for path in sorted(source.glob('target/scala-*/src_managed/main/org/'
                                   'ergoplatform/Version.scala')):
        match = re.search(r'VersionString\s*=\s*"([^"]+)"', path.read_text())
        if match:
            return match.group(1)
    raise BuildError(
        f'no generated Version.scala under {source}; the build is not compiled')


class Build:
    """One provisioned Scala build a devnet role can run."""

    def __init__(self, name, work_dir, manifest=None, declared=None):
        self.name = name
        self.work_dir = Path(work_dir)
        self.declared = dict(declared or {})
        self._manifest = manifest

    # ----- what is on disk -----

    @property
    def manifest_path(self):
        return self.work_dir / 'manifest.json'

    @property
    def available(self):
        """Is this build provisioned? A declared-but-unprovisioned patch
        build is not an error until a role asks to run it."""
        return self.manifest_path.exists() and self.classpath_file.exists()

    @property
    def manifest(self):
        if self._manifest is None:
            if not self.manifest_path.exists():
                raise BuildError(
                    f'build {self.name!r} is not provisioned: no '
                    f'{self.manifest_path}. Provision it with '
                    f'scripts/jvm_weak_blocks_oracle/provision.py '
                    f'--work-dir {self.work_dir}')
            self._manifest = json.loads(self.manifest_path.read_text())
        return self._manifest

    @property
    def classpath_file(self):
        return self.work_dir / 'classpath'

    @property
    def test_classpath_file(self):
        return self.work_dir / 'test-classpath'

    @property
    def source_dir(self):
        return self.work_dir / 'source'

    @property
    def sidecar_path(self):
        """Where a legacy manifest's computed fields are cached.

        BESIDE the work directory, never inside it: a provisioned build
        is immutable, and a devnet may be running out of it right now.
        """
        return self.work_dir.with_name(self.work_dir.name + '.computed.json')

    # ----- identity -----

    def _sidecar(self):
        try:
            return json.loads(self.sidecar_path.read_text())
        except (OSError, ValueError):
            return {}

    def _cache(self, **fields):
        cached = self._sidecar()
        cached.update(fields)
        cached['work_dir'] = str(self.work_dir)
        cached['note'] = ('computed for a manifest that predates the field; '
                          'the provisioned build itself is never modified')
        try:
            self.sidecar_path.write_text(json.dumps(cached, indent=2) + '\n')
        except OSError:
            # A read-only parent is not a reason to refuse the build; it
            # only costs the cache.
            pass
        return cached

    def _recorded(self, field, compute):
        """A manifest field, or the sidecar's cached computation of it."""
        recorded = self.manifest.get(field)
        if recorded:
            return recorded
        cached = self._sidecar().get(field)
        if cached:
            return cached
        value = compute()
        self._cache(**{field: value})
        return value

    def class_hash(self):
        """The recorded `class_dir_sha256`, computed for a legacy manifest."""
        return self._recorded(
            'class_dir_sha256',
            lambda: class_dir_sha256(self.classpath_file.read_text()))

    def app_version(self):
        """The `/info.appVersion` a node started from this build reports."""
        return self._recorded(
            'app_version', lambda: app_version_of(self.source_dir))

    def verify(self):
        """Recompute the class hash and REFUSE a build that has changed.

        Returns the manifest summary a role records as evidence. Raises
        `BuildError` on a mismatch: the alternative is attributing a
        measurement to a build that is not the one it was taken on.
        """
        if not self.available:
            raise BuildError(
                f'build {self.name!r} is not provisioned at {self.work_dir}')
        # The source commit first: the class hash says the output has not
        # moved since provisioning, this says it was provisioned from the
        # commit the registry names.
        pinned = self.declared.get('ergo_ref')
        provisioned = self.manifest.get('ergo_commit')
        if pinned and FULL_COMMIT.fullmatch(pinned) and provisioned != pinned:
            raise BuildError(
                f'build {self.name!r} at {self.work_dir} was provisioned from '
                f'{provisioned}, but builds.toml pins {pinned}. Re-provision '
                'it at the pinned commit before a role runs it.')
        expected = self.class_hash()
        try:
            actual = class_dir_sha256(self.classpath_file.read_text())
        except BuildError as error:
            # The usual cause is a work directory moved here from a
            # worktree that no longer exists: its `classpath` file still
            # names the old class directories.
            raise BuildError(
                f'build {self.name!r} at {self.work_dir} cannot be hashed: '
                f'{error}. Its classpath file names class directories that '
                'are gone (a work directory moved from a deleted worktree '
                'keeps the old paths); re-provision it before a role runs '
                'it.') from error
        if actual != expected:
            raise BuildError(
                f'build {self.name!r} at {self.work_dir} does not match its '
                f'recorded compiled output: class_dir_sha256 {actual} != '
                f'{expected}. Re-provision it, or fix the role that points '
                'here; a devnet number from an unidentified build is not '
                'evidence.')
        return self.summary(class_hash=actual)

    def summary(self, class_hash=None):
        """What a scenario's evidence records about the build it ran."""
        manifest = self.manifest
        return {
            'build': self.name,
            'work_dir': str(self.work_dir),
            'ergo_source': manifest.get('ergo_source'),
            'ergo_commit': manifest.get('ergo_commit'),
            'sigma_commit': manifest.get('sigma_commit'),
            'sigma_version': manifest.get('sigma_version'),
            'sigma_artifacts': manifest.get('sigma_artifacts'),
            'class_dir_sha256': class_hash or self.class_hash(),
            'class_dir_sha256_source': (
                'manifest' if manifest.get('class_dir_sha256')
                else f'computed, cached in {self.sidecar_path.name}'),
            'app_version': self.app_version(),
            'classpath': str(self.classpath_file),
            'description': self.declared.get('description'),
        }

    def __repr__(self):
        return f'Build({self.name!r}, {str(self.work_dir)!r})'


def _load_toml(path):
    import tomllib
    try:
        return tomllib.loads(Path(path).read_text())
    except OSError as error:
        raise BuildError(f'no build registry at {path}: {error}') from error


def _resolve_root(document):
    """Where the work directories live.

    Relative paths resolve against THIS worktree's repo root, because
    the provisioned builds are shared between worktrees (provisioning is
    expensive and the pins are the same) and so normally sit outside it.
    """
    raw = os.environ.get('MATRIX_BUILDS_ROOT') or document.get('root', '.')
    root = Path(os.path.expandvars(os.path.expanduser(raw)))
    return root if root.is_absolute() else (ROOT / root).resolve()


def registry(path=BUILDS_TOML):
    """Every declared build, provisioned or not, by name."""
    document = _load_toml(path)
    root = _resolve_root(document)
    declared = document.get('builds') or {}
    unknown = sorted(set(declared) - set(BUILD_NAMES))
    if unknown:
        raise BuildError(
            f'{path} declares build(s) {unknown} that no role can ask for; '
            f'the names are {list(BUILD_NAMES)}')
    missing = [name for name in BUILD_NAMES if name not in declared]
    if missing:
        raise BuildError(f'{path} does not declare {missing}')
    unpinned = sorted(name for name in BUILD_NAMES
                      if not FULL_COMMIT.fullmatch(
                          str(declared[name].get('ergo_ref', ''))))
    if unpinned:
        raise BuildError(
            f'{path}: ergo_ref of {unpinned} is not a full commit id; pin '
            'every build by its 40-hex commit, not a branch name')
    return {name: Build(name, root / declared[name]['work_dir'],
                        declared=declared[name])
            for name in BUILD_NAMES}


def load(name, path=BUILDS_TOML):
    """One build by name, verified. `BuildError` names the alternatives."""
    known = registry(path)
    if name not in known:
        available = ', '.join(
            f'{n}{"" if b.available else " (not provisioned)"}'
            for n, b in known.items())
        raise BuildError(f'unknown build {name!r}; declared builds: {available}')
    build = known[name]
    build.verify()
    return build


def provision_command(name, ergo_source, ergo_ref, path=BUILDS_TOML):
    """The `provision.py` invocation that would create build `name`.

    Printed in error messages so a missing build says how to make it
    rather than only that it is missing.
    """
    build = registry(path)[name]
    return (f'python3 scripts/jvm_weak_blocks_oracle/provision.py '
            f'--ergo-source {ergo_source} --ergo-ref {ergo_ref} '
            f'--work-dir {build.work_dir} --sigma-reuse')


def main(argv=None):
    """`builds.py [--verify|--self-test] [name]` — list or check the registry."""
    argv = list(sys.argv[1:] if argv is None else argv)
    if '--self-test' in argv:
        _self_test()
        return 0
    verify = '--verify' in argv
    names = [a for a in argv if not a.startswith('-')]
    known = registry()
    failures = 0
    for name in names or list(known):
        build = known[name]
        if not build.available:
            print(f'{name:8s} NOT PROVISIONED  {build.work_dir}')
            continue
        try:
            summary = build.verify() if verify else build.summary()
        except BuildError as error:
            failures += 1
            print(f'{name:8s} FAILED  {error}')
            continue
        print(f'{name:8s} {summary["ergo_commit"][:8]} '
              f'{summary["app_version"]} class={summary["class_dir_sha256"][:12]}')
    return 1 if failures else 0


def _self_test():
    """`builds.py` decides which build a measurement is attributed to, so
    its failure modes are tested rather than assumed."""
    import tempfile

    # ----- the hash sees content, paths and project membership -----
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)

        def classes(project, files):
            path = root / project / 'target' / 'scala-2.12' / 'classes'
            for name, body in files.items():
                target = path / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(body)
            return str(path)

        a = classes('source', {'A.class': b'aa', 'p/B.class': b'bb'})
        b = classes('ergo-core', {'C.class': b'cc'})
        cp = f'{a}{os.pathsep}/opt/x.jar{os.pathsep}{b}'
        first = class_dir_sha256(cp)
        # Stable across repeats and across classpath ORDER: a re-export
        # that lists the same directories differently is the same build.
        assert first == class_dir_sha256(cp), 'the hash must be stable'
        assert first == class_dir_sha256(
            f'{b}{os.pathsep}{a}'), 'directory order must not matter'
        # A changed class changes it.
        (Path(a) / 'A.class').write_bytes(b'ax')
        assert class_dir_sha256(cp) != first, 'a changed class must show'
        (Path(a) / 'A.class').write_bytes(b'aa')
        assert class_dir_sha256(cp) == first
        # So does the same bytes under a different name...
        (Path(a) / 'A.class').rename(Path(a) / 'A2.class')
        assert class_dir_sha256(cp) != first, 'a renamed class must show'
        (Path(a) / 'A2.class').rename(Path(a) / 'A.class')
        # ...and a classpath that is not an ergo build's at all.
        try:
            class_dir_sha256('/opt/x.jar')
        except BuildError as error:
            assert 'not an exported Runtime classpath' in str(error), error
        else:
            raise AssertionError('a jar-only classpath is not a build')

    # ----- a build refuses to run when its output has changed -----
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp) / '.work-probe'
        cls = work / 'source' / 'target' / 'scala-2.12' / 'classes'
        cls.mkdir(parents=True)
        (cls / 'X.class').write_bytes(b'one')
        (work / 'classpath').write_text(str(cls) + '\n')
        managed = (work / 'source' / 'target' / 'scala-2.12' / 'src_managed'
                   / 'main' / 'org' / 'ergoplatform')
        managed.mkdir(parents=True)
        (managed / 'Version.scala').write_text(
            'object Version {\n  val VersionString = "6.0.6-493-probe-SNAPSHOT"\n}\n')
        recorded = class_dir_sha256((work / 'classpath').read_text())
        (work / 'manifest.json').write_text(json.dumps({
            'ergo_commit': 'c0ffee' * 6 + 'abcd',
            'sigma_version': 's', 'class_dir_sha256': recorded}) + '\n')

        build = Build('probe', work)
        assert build.available, work
        summary = build.verify()
        assert summary['class_dir_sha256'] == recorded, summary
        assert summary['app_version'] == '6.0.6-493-probe-SNAPSHOT', summary
        assert summary['class_dir_sha256_source'] == 'manifest', summary

        # THE failure this module exists for: the compiled output moved
        # under a build a role is about to run.
        (cls / 'X.class').write_bytes(b'two')
        try:
            build.verify()
        except BuildError as error:
            assert 'does not match its recorded compiled output' in str(error), error
        else:
            raise AssertionError('a changed build must be refused')
        (cls / 'X.class').write_bytes(b'one')
        assert build.verify()['class_dir_sha256'] == recorded

        # ----- a LEGACY manifest (no class hash) is tolerated, cached,
        # and the immutable build directory is never written to -----
        legacy_work = Path(tmp) / '.work-legacy'
        import shutil
        shutil.copytree(work, legacy_work)
        (legacy_work / 'manifest.json').write_text(json.dumps({
            'ergo_commit': 'c0ffee' * 6 + 'abcd', 'sigma_version': 's'}) + '\n')
        legacy_cls = legacy_work / 'source/target/scala-2.12/classes'
        # The copied classpath still names the ORIGINAL directory; point
        # it at this build's own output, or the test would hash a
        # directory it never touches and nothing it changes would show.
        (legacy_work / 'classpath').write_text(str(legacy_cls) + '\n')
        before = sorted(p.name for p in legacy_work.iterdir())
        legacy = Build('legacy', legacy_work)
        expected = class_dir_sha256(str(legacy_cls))
        assert legacy.class_hash() == expected, legacy.class_hash()
        assert legacy.sidecar_path.exists(), legacy.sidecar_path
        assert legacy.sidecar_path.parent == legacy_work.parent, \
            'the sidecar goes BESIDE the build, never inside it'
        assert sorted(p.name for p in legacy_work.iterdir()) == before, \
            'a provisioned build is immutable'
        assert 'computed' in legacy.summary()['class_dir_sha256_source']
        # And the cached hash is then what a later change is refused against.
        (legacy_cls / 'X.class').write_bytes(b'three')
        try:
            legacy.verify()
        except BuildError as error:
            assert 'does not match' in str(error), error
        else:
            raise AssertionError('a legacy build must still be pinned')

        # ----- the registry pins a COMMIT, and a build provisioned from
        # any other commit is refused -----
        pinned = Build('pinned', work, declared={'ergo_ref': 'c0ffee' * 6 + 'abcd'})
        assert pinned.verify()['ergo_commit'] == 'c0ffee' * 6 + 'abcd'
        moved = Build('moved', work, declared={'ergo_ref': 'beef' * 10})
        try:
            moved.verify()
        except BuildError as error:
            assert 'was provisioned from' in str(error), error
        else:
            raise AssertionError('a build from another commit must be refused')

    # ----- the registry -----
    known = registry()
    # Every entry is pinned by a full commit id: a branch name resolves to
    # whatever the branch points at on the day a build is provisioned.
    for name, build in known.items():
        assert FULL_COMMIT.fullmatch(build.declared.get('ergo_ref', '')), \
            (name, build.declared)
    with tempfile.TemporaryDirectory() as tmp:
        branchy = Path(tmp) / 'builds.toml'
        branchy.write_text(BUILDS_TOML.read_text().replace(
            'ergo_ref = "62c10315e1ebcac4480dba6bacdc2100a38119e5"',
            'ergo_ref = "weak-blocks"'))
        try:
            registry(branchy)
        except BuildError as error:
            assert 'not a full commit id' in str(error), error
        else:
            raise AssertionError('a branch name in the registry must be refused')
    assert list(known) == list(BUILD_NAMES), list(known)
    # The work directory each name resolves to. The pinned baselines are
    # named by their commit, the M4 patch builds by their own name, and a
    # `+` in a name never reaches a path.
    by_commit = {'stock': '.work-62c10315', 'base': '.work-a1bd938e',
                 'base+2506': '.work-base-2506-f7cc55dd',
                 '2563f+2506': '.work-2563f-plus-2506'}
    for name in BUILD_NAMES:
        assert known[name].work_dir.name == by_commit.get(
            name, f'.work-{name}'), known[name]
        assert '+' not in known[name].work_dir.name, known[name]
    # The re-measure's six builds, pinned at the commits their runs are
    # attributed to (REVIEW-2563 §3.2 and the #2562 two-miner run).
    for name, commit in (
            ('base', 'a1bd938effb7f5acabfe5230a5ef20fe0d50ae62'),
            ('base+2506', 'f7cc55dd29b3c0a06e4f7f3eafbe1bef4044081e'),
            ('2563f', '13fc25df26f13b2f4ee6c38c87f5cb7d0765b71b'),
            ('2563f+2506', 'd3d69c610d8a02b13971ac68b52978b5aeb87797'),
            ('2562f', '0efc06fef33f79a6f2b73084681e69f132350aef'),
            ('soak', 'abf02c053946ae780fabcf5ad48b2d1e5680e023')):
        assert known[name].declared['ergo_ref'] == commit, known[name].declared
    # `root` is the shared archive, resolved against this worktree's repo
    # root, so every sibling checkout finds the same directories.
    # MATRIX_BUILDS_ROOT, when set, overrides that root.
    expected_root = (_resolve_root({}) if os.environ.get('MATRIX_BUILDS_ROOT')
                     else (ROOT / '../matrix-evidence/scala-builds').resolve())
    assert known['base'].work_dir.parent == expected_root, known['base'].work_dir
    # A build moved here from a deleted worktree keeps a classpath that
    # names the old directories. It is refused with the reason, never
    # hashed as an empty build.
    with tempfile.TemporaryDirectory() as tmp:
        moved = Path(tmp) / '.work-moved'
        moved.mkdir()
        (moved / 'classpath').write_text(
            f'{tmp}/gone/source/target/scala-2.12/classes\n')
        (moved / 'manifest.json').write_text(json.dumps({
            'ergo_commit': 'ab' * 20, 'class_dir_sha256': '00' * 32}) + '\n')
        try:
            Build('moved', moved, declared={'ergo_ref': 'ab' * 20}).verify()
        except BuildError as error:
            assert 're-provision it' in str(error), error
            assert 'which does not exist' in str(error), error
        else:
            raise AssertionError('a classpath into a deleted tree must be refused')
    try:
        load('nope')
    except BuildError as error:
        assert 'unknown build' in str(error) and 'stock' in str(error), error
    else:
        raise AssertionError('an unknown build name must be refused')
    print('builds self-test OK: class hashing, verification and the registry')


if __name__ == '__main__':
    raise SystemExit(main())
