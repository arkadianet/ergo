#!/usr/bin/env python3
"""Build an isolated pinned node classpath with one return-value observation."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tarfile

HERE = Path(__file__).resolve().parent
SOURCE = HERE / '.work/source'
REFERENCE = Path(os.environ.get('ERGO_REFERENCE', Path.home() / 'coding/development/arkadianet/ergo-scala'))
REVISION = '5528ef569a41ebccbc8658212e6ee3c97d990b96'  # Ergo v6.0.5


def main():
    # Extraction overlays files and sbt has no clean step, so stale sources or
    # outputs could enter `Runtime / fullClasspath`. Drop the tree and the marker
    # first: a failed build must not leave `run.py` accepting an old classpath.
    marker = HERE / '.work/classpath'
    if marker.exists():
        marker.unlink()
    if SOURCE.exists():
        shutil.rmtree(SOURCE)
    SOURCE.mkdir(parents=True)
    archive = HERE / '.work/source.tar'
    with archive.open('wb') as output:
        subprocess.run(['git', '-C', str(REFERENCE), 'archive', REVISION], stdout=output, check=True)
    with tarfile.open(archive) as source:
        source.extractall(SOURCE, filter='data')
    archive.unlink()
    path = SOURCE / 'src/main/scala/org/ergoplatform/nodeView/state/UtxoState.scala'
    original = path.read_text()
    call = 'ErgoState.execTransactions(transactions, currentStateContext, ergoSettings.nodeSettings)(checkBoxExistence)'
    assert hashlib.sha256(original.encode()).hexdigest() == '4bc8c1b8f9a49087f50cbd3e45f54bba1e83482f85dde396db13ad89e9b45e6e'
    assert original.count(call) == 1
    path.write_text(original.replace(call, 'CostObservation.observe(' + call + ')'))
    shutil.copyfile(HERE / 'CostObservation.scala', path.with_name('CostObservation.scala'))
    (HERE / '.work/observation-source.sha256').write_text(hashlib.sha256(original.encode()).hexdigest() + '\n')
    command = ['sbt', '-batch', 'set ThisBuild / version := "6.0.5"', 'export Runtime / fullClasspath']
    log = HERE / '.work/provision.log'
    with log.open('w') as output:
        environment = os.environ.copy()
        environment.pop('SIGMASTATE_VERSION', None)
        subprocess.run(command, cwd=SOURCE, env=environment, stdout=output, stderr=subprocess.STDOUT, check=True)
    lines = log.read_text().splitlines()
    classpath = next(line for line in reversed(lines) if line.startswith('/') and 'scala-library' in line)
    marker.write_text(classpath + '\n')
    print('Provisioned Ergo 6.0.5; one UtxoState return-value wrapper')


if __name__ == '__main__':
    main()
