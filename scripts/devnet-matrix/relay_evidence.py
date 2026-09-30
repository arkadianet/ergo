"""Replayable, bounded-memory relay logs; one JSON string per tailed entry."""
import json
from pathlib import Path


class LineFile:
    def __init__(self, path, count=0):
        self.path = Path(path)
        self.count = count

    def __len__(self):
        return self.count

    def __iter__(self):
        count = 0
        with self.path.open(encoding='utf-8') as source:
            for record in source:
                line = json.loads(record)
                if not isinstance(line, str):
                    raise ValueError(f'{self.path}: expected a JSON string')
                count += 1
                yield line
        if count != self.count:
            raise ValueError(f'{self.path}: expected {self.count} entries, found {count}')

    def reference(self):
        return {'path': self.path.name, 'line_count': self.count}


def source_lines(result, evidence_dir=None):
    """Inline archives need no directory; sidecars resolve beside steady.json."""
    if 'source_lines' in result:
        return result['source_lines']
    if evidence_dir is None:
        raise ValueError('an evidence directory is required for relay log sidecars')
    return {node: LineFile(Path(evidence_dir) / ref['path'], ref['line_count'])
            for node, ref in result['source_line_files'].items()}
