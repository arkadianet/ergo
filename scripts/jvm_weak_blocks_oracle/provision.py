#!/usr/bin/env python3
"""Build the pinned Scala weak-blocks node + its sigma-state fork snapshot into an isolated classpath."""
import hashlib
import json
import os
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
WORK = HERE / '.work'
ERGO_REPO = 'https://github.com/ergoplatform/ergo.git'
ERGO_COMMIT = '31a8de804f7328704f2753a1cf151dda8f64689f'
SIGMA_REPO = 'https://github.com/ScorexFoundation/sigmastate-interpreter.git'
SIGMA_COMMIT = '368a860be033af94aa14895381f42099b3646db6'
SIGMA_VERSION = '6.0.5-22-368a860b-SNAPSHOT'
IVY_LOCAL = Path.home() / '.ivy2/local/org.scorexfoundation'


def run(cmd, cwd, log):
    with log.open('a') as out:
        out.write('$ ' + ' '.join(cmd) + '\n')
        subprocess.run(cmd, cwd=cwd, stdout=out, stderr=subprocess.STDOUT, check=True)


def checkout(url, commit, dest, log):
    if not (dest / '.git').exists():
        run(['git', 'clone', '--filter=blob:none', url, str(dest)], HERE, log)
    run(['git', 'fetch', 'origin', commit], dest, log)
    run(['git', 'checkout', '--detach', commit], dest, log)
    head = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=dest, capture_output=True, text=True, check=True).stdout.strip()
    assert head == commit, (head, commit)


def export_classpath(source, config, log):
    marker = WORK / f'{config.lower()}-classpath.log'
    run(['sbt', '-batch', f'export {config} / fullClasspath'], source, marker)
    lines = marker.read_text().splitlines()
    return next(line for line in reversed(lines) if line.startswith('/') and 'scala-library' in line)


def main():
    WORK.mkdir(exist_ok=True)
    for name in ('classpath', 'test-classpath', 'manifest.json'):
        (WORK / name).unlink(missing_ok=True)
    log = WORK / 'provision.log'
    log.unlink(missing_ok=True)

    sigma = WORK / 'sigma'
    checkout(SIGMA_REPO, SIGMA_COMMIT, sigma, log)
    # The ergo build pins this exact SNAPSHOT string; publish both Scala binaries it consumes.
    run(['sbt', '-batch', f'set ThisBuild / version := "{SIGMA_VERSION}"', '+publishLocal'], sigma, log)
    jars = sorted(p for p in IVY_LOCAL.glob(f'sigma-state_*/{SIGMA_VERSION}/jars/*.jar'))
    assert jars, f'no sigma-state jars published under {IVY_LOCAL}'

    ergo = WORK / 'source'
    checkout(ERGO_REPO, ERGO_COMMIT, ergo, log)
    env = os.environ.copy()
    env['SIGMASTATE_VERSION'] = SIGMA_VERSION
    os.environ.update(env)
    runtime = export_classpath(ergo, 'Runtime', log)
    test = export_classpath(ergo, 'Test', log)
    (WORK / 'classpath').write_text(runtime + '\n')
    (WORK / 'test-classpath').write_text(test + '\n')
    manifest = {
        'ergo_commit': ERGO_COMMIT,
        'sigma_commit': SIGMA_COMMIT,
        'sigma_version': SIGMA_VERSION,
        'sigma_artifacts': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in jars},
    }
    (WORK / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(f'Provisioned ergo weak-blocks {ERGO_COMMIT[:8]} with sigma {SIGMA_VERSION}')


if __name__ == '__main__':
    main()
