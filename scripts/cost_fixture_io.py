"""Cost fixture storage; gzip headers omit filenames and timestamps.

Evidence hashes describe uncompressed JSON bytes, independent of storage.
Readers prefer .json.gz and also accept the published plain .json fixtures.
"""
import gzip
from pathlib import Path


def fixture_path(path):
    path = Path(path)
    if path.suffix == '.json':
        compressed = path.with_suffix('.json.gz')
        return compressed if compressed.exists() else path
    if path.name.endswith('.json.gz') and not path.exists():
        return path.with_suffix('')
    return path


def read_fixture_text(path):
    path = fixture_path(path)
    data = path.read_bytes()
    if path.suffix == '.gz':
        data = gzip.decompress(data)
    return data.decode('utf-8')


def write_fixture_text(path, text):
    path = Path(path)
    if path.suffix == '.json':
        path = path.with_suffix('.json.gz')
    staging = path.with_name(path.name + '.tmp')
    try:
        with staging.open('wb') as output:
            if path.suffix == '.gz':
                with gzip.GzipFile(filename='', mode='wb', fileobj=output, mtime=0) as archive:
                    archive.write(text.encode('utf-8'))
            else:
                output.write(text.encode('utf-8'))
        staging.replace(path)
        if path.name.endswith('.json.gz'):
            path.with_suffix('').unlink(missing_ok=True)
    finally:
        staging.unlink(missing_ok=True)


def fixture_paths(directory, pattern='*'):
    """Select each JSON fixture once, preferring gzip when both exist."""
    directory = Path(directory)
    paths = {fixture_path(path) for path in directory.glob(pattern + '.json')}
    paths.update(directory.glob(pattern + '.json.gz'))
    return sorted(paths)
