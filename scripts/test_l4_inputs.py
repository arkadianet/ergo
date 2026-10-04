"""Offline regressions for complete capture installation and recovery."""

import io
from pathlib import Path
import tarfile
import tempfile
import unittest

import l4_inputs


class InputTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.directory = root / "captures"
        self.directory.mkdir()
        self.archive = root / "bundle.tar.gz"
        self.data = {"headers_1_2.json.gz": b"headers", "tx_costs_1_2.json.gz": b"costs"}
        self.bundle(self.data)
        self.manifest = dict(archive_sha256=l4_inputs.digest(self.archive), files={})
        for name, data in self.data.items():
            self.manifest["files"][name] = l4_inputs.hashlib.sha256(data).hexdigest()

    def bundle(self, data):
        with tarfile.open(self.archive, "w:gz") as bundle:
            for name, contents in data.items():
                member = tarfile.TarInfo(name)
                member.size = len(contents)
                bundle.addfile(member, io.BytesIO(contents))

    def test_install_and_repair_preserve_unrelated_files(self):
        unrelated = self.directory / "hand-curated.json"
        unrelated.write_text("preserve")
        l4_inputs.install(self.archive, self.directory, self.manifest)
        self.assertTrue(l4_inputs.verified(self.directory, self.manifest))
        for change in ("delete", "corrupt"):
            with self.subTest(change=change):
                path = self.directory / next(iter(self.data))
                if change == "delete":
                    path.unlink()
                else:
                    path.write_bytes(b"changed")
                self.assertFalse(l4_inputs.verified(self.directory, self.manifest))
                l4_inputs.install(self.archive, self.directory, self.manifest)
                self.assertTrue(l4_inputs.verified(self.directory, self.manifest))
                self.assertEqual(unrelated.read_text(), "preserve")

    def test_marker_without_captures_is_not_ready(self):
        (self.directory / l4_inputs.MARKER).write_text(self.manifest["archive_sha256"])
        self.assertFalse(l4_inputs.verified(self.directory, self.manifest))

    def test_bad_archive_or_inventory_never_publishes(self):
        for data in ({"missing.json.gz": b"wrong"}, {"../escape": b"wrong"}):
            with self.subTest(data=data):
                self.bundle(data)
                with self.assertRaisesRegex(ValueError, "SHA-256"):
                    l4_inputs.install(self.archive, self.directory, self.manifest)
                updated = dict(self.manifest, archive_sha256=l4_inputs.digest(self.archive))
                with self.assertRaisesRegex(ValueError, "inventory"):
                    l4_inputs.install(self.archive, self.directory, updated)
                self.assertEqual(list(self.directory.iterdir()), [])

    def test_wrong_capture_hash_never_replaces_existing_capture(self):
        path = self.directory / next(iter(self.data))
        path.write_bytes(b"existing")
        self.manifest["files"][path.name] = "incorrect"
        with self.assertRaisesRegex(ValueError, "capture SHA-256"):
            l4_inputs.install(self.archive, self.directory, self.manifest)
        self.assertEqual(path.read_bytes(), b"existing")
        self.assertFalse((self.directory / l4_inputs.MARKER).exists())


if __name__ == "__main__":
    unittest.main()
