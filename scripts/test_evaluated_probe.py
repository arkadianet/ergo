"""Direct-probe provenance tests; JVM execution is a separate integration check."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
spec = importlib.util.spec_from_file_location('evaluated_probe', Path(__file__).with_name('gen-evaluated-probe.py'))
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class SourceSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        subprocess.run(['git', 'init', '-q', str(self.root)], check=True)
        subprocess.run(['git', '-C', str(self.root), 'config', 'user.name', 'Fixture'], check=True)
        subprocess.run(['git', '-C', str(self.root), 'config', 'user.email', 'fixture@example.invalid'], check=True)
        script = self.root / probe.SCRIPT
        script.parent.mkdir(parents=True)
        script.write_bytes(b'object Original {}\n')
        (self.root / probe.GENERATOR).write_bytes(b'fixture generator source\n')
        manifest = self.root / 'test-vectors/ergo-sigma/verify/manifest.json'
        manifest.parent.mkdir(parents=True)
        manifest.write_text(json.dumps({'scala': {'sigmastate_version': '6.0.6'}, 'rent_run': {'executed': 99}}))
        subprocess.run(['git', '-C', str(self.root), 'add', '.'], check=True)
        subprocess.run(['git', '-C', str(self.root), 'commit', '-qm', 'fixture'], check=True)

    def test_clean_source_archive_is_exact_and_independent_of_later_edits(self):
        archive, state = probe.snapshot_source(self.root)
        self.assertTrue(state['source_matches_base'])
        self.assertFalse(state['checkout_dirty_before_snapshot'])
        self.assertEqual(state['source_revision'], state['base_revision'])
        original = archive.read_bytes()
        (self.root / probe.SCRIPT).write_bytes(b'object Changed {}\n')
        self.assertEqual(archive.read_bytes(), original)
        self.assertEqual(probe.sha(original), state['source_sha256'])

    def test_dirty_source_does_not_claim_base_as_exact_source_revision(self):
        (self.root / probe.SCRIPT).write_bytes(b'object Changed {}\n')
        archive, state = probe.snapshot_source(self.root)
        self.assertFalse(state['source_matches_base'])
        self.assertTrue(state['checkout_dirty_before_snapshot'])
        self.assertIsNone(state['source_revision'])
        self.assertEqual(archive.read_bytes(), b'object Changed {}\n')
        self.assertNotEqual(state['tracked_source_at_base_sha256'], state['source_sha256'])

    def test_capture_executes_snapshot_and_does_not_inherit_unrelated_run(self):
        original_run = subprocess.run
        original_output = probe.output
        sent = []

        def run(command, **kwargs):
            if command[0] != 'scala-cli':
                return original_run(command, **kwargs)
            sent.append(command)
            self.assertEqual(Path(command[3]).read_bytes(), b'object Original {}\n')
            (self.root / probe.SCRIPT).write_bytes(b'object Changed {}\n')
            jar = self.root / 'circe-core_2.12-0.14.15.jar'
            jar.write_bytes(b'unit-test-jar-content')
            runtime = ('DIRECT_PROBE_RUNTIME_JSON=' + json.dumps({'java.class.path': str(jar), 'java.runtime.version': 'test-runtime'}) + '\n').encode()
            return subprocess.CompletedProcess(command, 0, b'{"cases":[{"result":1}]}', runtime)

        def output(root, *command):
            return original_output(root, *command) if command[0] == 'git' else 'test-tool-version'

        destination = Path('direct.json')
        with patch.object(probe.subprocess, 'run', side_effect=run), patch.object(probe, 'output', side_effect=output):
            probe.capture(self.root, 'jitcost_probe', destination, b'')
        captured = json.loads((self.root / destination).read_text())
        self.assertNotIn('rent_run', captured['manifest'])
        self.assertEqual(captured['manifest']['tool']['actual_runtime']['resolved_jars'][0]['name'], 'circe-core_2.12-0.14.15.jar')
        self.assertEqual(captured['manifest']['tool']['actual_runtime']['java.runtime.version'], 'test-runtime')
        self.assertEqual(captured['manifest']['run']['executed'], 1)
        self.assertEqual(captured['manifest']['tool']['source_state']['source_sha256'], probe.sha(b'object Original {}\n'))
        self.assertEqual(captured['manifest']['run']['command_argv'], sent[0])
        self.assertFalse((self.root / 'direct.json.gz').exists())


class ResponseTests(unittest.TestCase):
    def test_direct_cases_are_preserved(self):
        self.assertEqual(probe.parse_response(b'{"cases":[{"exception":"expected"}]}')['cases'], [{'exception': 'expected'}])

    def test_response_requires_cases_array(self):
        for raw in [b'{}', b'{"cases":0}', b'[]', b'not json']:
            with self.assertRaises((ValueError, json.JSONDecodeError)):
                probe.parse_response(raw)


if __name__ == '__main__':
    unittest.main()
