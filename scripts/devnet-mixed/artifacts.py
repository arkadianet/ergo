"""Deterministic campaign evidence archives; member paths are relative to the repo."""
import gzip
import hashlib
import io
from pathlib import Path
import tarfile


def read_members(path):
    if not path.exists():
        return {}
    with tarfile.open(path, 'r:gz') as archive:
        return {member.name: archive.extractfile(member).read()
                for member in archive.getmembers() if member.isfile()}


def write_archive(path, members):
    """Write sorted regular files with fixed metadata and gzip -n semantics."""
    temporary = path.with_suffix('.tmp')
    with temporary.open('wb') as raw:
        with gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w', format=tarfile.USTAR_FORMAT) as archive:
                for name, data in sorted(members.items()):
                    member = tarfile.TarInfo(name)
                    member.size = len(data)
                    member.mode = 0o644
                    archive.addfile(member, io.BytesIO(data))
    temporary.replace(path)
    index = Path(str(path).removesuffix('.tar.gz') + '.index.txt')
    index.write_text(''.join(f'{name}\t{len(data)}\t{hashlib.sha256(data).hexdigest()}\n'
                             for name, data in sorted(members.items())))
    return index
