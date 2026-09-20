//! Oracle: test-vectors/ergo-sigma/cost-total/mainnet-epochs.json.gz
//! Manifest-only preservation and historical context checks require no live node.

// ----- helpers -----

fn python_check(code: &str) {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let output = std::process::Command::new("python3")
        .current_dir(root)
        .args([
            "-c",
            &format!(
                "import runpy, json\nm = runpy.run_path('scripts/l4-results-manifest.py')\n{code}"
            ),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// ----- round-trips -----

#[test]
fn l4_manifest_refresh_preserves_recorded_bytes() {
    python_check(
        r#"
from pathlib import Path
for path in Path('test-vectors/ergo-sigma/cost-ledger/results').glob('l4-*.json'):
    raw = path.read_bytes()
    original = m['recorded_bytes'](raw)
    for manifest in [{'test': 'first'}, {'test': 'second, with } and é'}]:
        raw = m['with_manifest'](raw, manifest)
        assert m['recorded_bytes'](raw) == original
        decoded = json.loads(raw)
        assert decoded.pop('manifest') == manifest
        assert decoded == json.loads(original)
raw = b'{\n "number": 1.00, "escaped": "\\u0061", "nested": {"manifest": 1}\n}\n'
assert m['recorded_bytes'](m['with_manifest'](raw, {})) == raw
# Exercise the actual file-writing CLI with collection isolated from live tools.
import sys, tempfile
from unittest.mock import patch
with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
    path = Path(directory) / 'result.json'
    path.write_bytes(raw)
    with patch.dict(m['main'].__globals__, {'collect': lambda *args: {'test': 'collected'}}):
        with patch.object(sys, 'argv', ['l4-results-manifest.py', '--manifest-only', str(path), '--log', 'unused.log']):
            m['main']()
            first = path.read_bytes()
            m['main']()
    assert path.read_bytes() == first
    assert m['recorded_bytes'](first) == raw
"#,
    );
}

// ----- error paths -----

#[test]
fn l4_manifest_unsupported_layout_rejected() {
    python_check(
        r#"
try:
    m['with_manifest'](b'{"result": 1, "manifest": {}}', {})
except ValueError:
    pass
else:
    raise AssertionError('must not rewrite arbitrary result fields')
try:
    m['range_context']([{'start': 0, 'end': 1}])
except ValueError:
    pass
else:
    raise AssertionError('must not silently omit uncovered heights')
"#,
    );
}

// ----- oracle parity -----

#[test]
fn l4_manifest_activation_boundary_maps_both_versions() {
    python_check(
        r#"
context = m['range_context']([{'start': 889855, 'end': 889856}])
segments = context['ranges'][0]['segments']
assert [s['heights'] for s in segments] == [[889855, 889855], [889856, 889856]]
assert [s['block_version'] for s in segments] == [2, 3]
assert [s['activated_script_version'] for s in segments] == [1, 2]
for segment in segments:
    assert set(segment['params']) == {'4', '5', '6', '7', '8'}
    assert segment['params'] == {'4': 8001091, '5': 100, '6': 2407, '7': 100, '8': 184}
from pathlib import Path
for path in Path('test-vectors/ergo-sigma/cost-ledger/results').glob('l4-*.json'):
    data = json.loads(path.read_bytes())
    mapped = m['range_context'](data['ranges'])
    assert len(mapped['ranges']) == len(data['ranges'])
    assert data['manifest']['context'] == mapped
    assert data['manifest']['evidence']['recorded_results_bytes_without_manifest'] == m['digest'](m['recorded_bytes'](path.read_bytes()))
"#,
    );
}

#[test]
fn l4_manifest_compressed_vectors_preserve_input_hashes() {
    python_check(
        r#"
from pathlib import Path
import gzip
actual = m['vector_evidence']()
assert len([name for name in actual if '/tx_costs_' in name]) == 389
for name, sha in actual.items():
    path = Path(name)
    compressed = path.with_suffix('.json.gz')
    if compressed.exists():
        raw = compressed.read_bytes()
        assert raw[3:8] == bytes(5), name
        assert m['digest'](gzip.decompress(raw)) == sha, name
    if path.exists():
        assert m['digest'](path.read_bytes()) == sha, name
for path in Path('test-vectors/ergo-sigma/cost-ledger/results').glob('l4-*.json'):
    data = json.loads(path.read_bytes())
    for name, sha in data['manifest']['evidence'].items():
        if name.startswith('test-vectors/mainnet/'):
            assert actual[name] == sha, name
"#,
    );
}
