"""Combined release packaging and fail-closed publication inventory tests."""

import hashlib
import json
from pathlib import Path
import shutil
import stat
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile
import warnings

from test_release_policy import release


class ReleaseLayout(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.fixture.cleanup)
        cls.base = Path(cls.fixture.name)
        cls.sha = "b" * 40
        # Follow the checkout version so the fixture survives the next release bump.
        cls.version = release.tomllib.loads((release.ROOT / "Cargo.toml").read_text())["workspace"]["package"]["version"]
        cls.tag = "v" + cls.version
        cls.binaries = cls.base / "binaries"
        cls.binaries.mkdir()
        for name in ("ergo-node", "ergo-wallet", "ergo-walletd", "ergo-node.exe", "ergo-wallet.exe", "ergo-walletd.exe"):
            (cls.binaries / name).write_bytes(f"fixture {name}\n".encode())
        cls.inputs = cls.base / "inputs"
        cls.inputs.mkdir()
        for target in release.TARGETS:
            with mock.patch.object(release, "git", side_effect=cls.fixture_git), \
                 mock.patch.object(release.subprocess, "run", side_effect=cls.run_binary), \
                 mock.patch.object(release, "smoke_node", side_effect=cls.smoke_node), \
                 mock.patch.object(release, "smoke_walletd", side_effect=cls.smoke_walletd):
                release.package(target, cls.binaries, cls.inputs / target, tag=cls.tag, sha=cls.sha)

    @classmethod
    def fixture_git(cls, *args, **kwargs):
        return "1720000000" if args[0] == "show" else cls.sha

    @classmethod
    def run_binary(cls, command, **kwargs):
        binary = Path(command[0])
        if binary.read_bytes() != (cls.binaries / binary.name).read_bytes():
            raise AssertionError("smoke did not execute the extracted binary")
        if not binary.suffix and binary.stat().st_mode & 0o111 != 0o111:
            raise AssertionError("extracted binary lost executable permissions")
        return subprocess.CompletedProcess(command, 0, stdout=f"{binary.name.removesuffix('.exe')} {cls.version}\n")

    @classmethod
    def smoke_node(cls, binary, config, work):
        if binary.parent != config.parent.parent or not config.is_file() or not work.is_dir():
            raise AssertionError("node smoke must use extracted archive configuration")
        extension = ".exe" if binary.suffix else ""
        if not (binary.parent / ("ergo-wallet" + extension)).is_file():
            raise AssertionError("combined archive must contain the wallet during node smoke")

    @classmethod
    def smoke_walletd(cls, binary, config, work):
        if binary.parent != config.parent.parent or not config.is_file():
            raise AssertionError("walletd smoke must use extracted seed configuration")
        if binary.read_bytes() != (cls.binaries / binary.name).read_bytes():
            raise AssertionError("walletd smoke must execute the extracted binary")
        if 'mode = "seed"' not in config.read_text():
            raise AssertionError("walletd smoke requires the seed template")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.input = self.root / "input"
        shutil.copytree(self.inputs, self.input)
        self.output = self.root / "public"
        self.target = release.TARGETS[0]

    def archive(self, target=None):
        target = target or self.target
        return self.input / target / "public" / release.archive_name(target)

    def receipt_path(self, target=None):
        target = target or self.target
        return self.input / target / "internal" / f"receipt-{target}.json"

    def receipt(self, target=None):
        return json.loads(self.receipt_path(target).read_text())

    def mutate_receipt(self, edit, target=None):
        receipt = self.receipt(target)
        edit(receipt)
        release.write_json(self.receipt_path(target), receipt)

    def aggregate(self):
        release.aggregate(self.input, self.output, self.tag, self.sha)

    def rewrite_archive(self, edit, target=None):
        target = target or self.target
        path = self.archive(target)
        stage = self.root / "rewritten"
        stage.mkdir()
        if target.endswith("windows-msvc"):
            with zipfile.ZipFile(path) as bundle:
                bundle.extractall(stage)
        else:
            with tarfile.open(path) as bundle:
                bundle.extractall(stage, filter="data")
        edit(stage)
        release.build_archive(stage, path, target, 1720000000)
        self.mutate_receipt(lambda info: info.update(size=path.stat().st_size, sha256=release.checksum(path)), target)

    def test_combined_archive_inventory_and_metadata_on_all_targets(self):
        for target in release.TARGETS:
            with self.subTest(target=target):
                receipt = self.receipt(target)
                self.assertEqual(receipt["smoke"], release.SMOKE_CHECKS)
                if target.endswith("windows-msvc"):
                    with zipfile.ZipFile(self.archive(target)) as bundle:
                        names = set(bundle.namelist())
                        metadata = json.loads(bundle.read("release-info.json"))
                else:
                    with tarfile.open(self.archive(target)) as bundle:
                        names = {member.name for member in bundle if member.isfile()}
                        metadata = json.load(bundle.extractfile("release-info.json"))
                        for name in release.executable_names(target):
                            self.assertEqual(bundle.getmember(name).mode, 0o755)
                self.assertEqual(names, set(release.SUPPORT_FILES) | set(release.executable_names(target)) | {"release-info.json"})
                self.assertEqual(metadata, {key: receipt[key] for key in ("schema_version", "tag", "version", "sha", "target", "executables")})
                for name in release.executable_names(target):
                    self.assertEqual(receipt["executables"][name]["sha256"], release.checksum(self.binaries / name))
                self.assertEqual({p.name for p in self.archive(target).parent.iterdir()}, {release.archive_name(target)})

    def test_manifest_and_checksums_agree_and_only_eight_assets_are_public(self):
        self.aggregate()
        manifest = json.loads((self.output / "release.json").read_text())
        self.assertEqual(set(manifest["targets"]), set(release.TARGETS))
        self.assertEqual(len(list(self.output.iterdir())), 8)
        rows = (self.output / "SHA256SUMS").read_bytes().decode("utf-8").splitlines()
        self.assertEqual(len(rows), 7)
        self.assertEqual([row[66:] for row in rows], sorted(row[66:] for row in rows))
        for row in rows:
            self.assertRegex(row, r"^[0-9a-f]{64}  [^ /\\\r\n]+$")
            digest, name = row.split("  ")
            self.assertEqual(digest, release.checksum(self.output / name))
            if name != "release.json":
                info = next(info for info in manifest["targets"].values() if info["archive"] == name)
                self.assertEqual(info["sha256"], digest)
                self.assertEqual(info["size"], (self.output / name).stat().st_size)
        self.assertNotIn("SHA256SUMS", [row[66:] for row in rows])
        release.verify_assets(self.output, self.tag, self.sha)

    def test_repackaging_identical_inputs_is_byte_identical(self):
        for target in (self.target, release.TARGETS[-1]):
            output = self.root / target
            with mock.patch.object(release, "git", side_effect=self.fixture_git), \
                 mock.patch.object(release.subprocess, "run", side_effect=self.run_binary), \
                 mock.patch.object(release, "smoke_node", side_effect=self.smoke_node), \
                 mock.patch.object(release, "smoke_walletd", side_effect=self.smoke_walletd):
                release.package(target, self.binaries, output, tag=self.tag, sha=self.sha)
            self.assertEqual((output / "public" / release.archive_name(target)).read_bytes(), self.archive(target).read_bytes())

    def test_missing_or_extra_transport_files_are_rejected_before_output(self):
        for name in ("ergo-node", "stale.sha256", "release-target.json"):
            with self.subTest(name=name):
                extra = self.input / name
                extra.write_text("unexpected")
                with self.assertRaisesRegex(ValueError, "release inputs"):
                    self.aggregate()
                self.assertFalse(self.output.exists())
                extra.unlink()
        self.receipt_path().unlink()
        with self.assertRaisesRegex(ValueError, "release inputs"):
            self.aggregate()

    def test_missing_target_is_rejected_unless_explicit_local_fixture(self):
        for target in release.TARGETS[1:]:
            shutil.rmtree(self.input / target)
        with self.assertRaisesRegex(ValueError, "release inputs"):
            self.aggregate()
        release.aggregate(self.input, self.output, self.tag, self.sha, test_target=self.target)
        self.assertEqual(len(list(self.output.iterdir())), 3)
        release.verify_assets(self.output, self.tag, self.sha, test_target=self.target)
        with self.assertRaisesRegex(ValueError, "public assets"):
            release.verify_assets(self.output, self.tag, self.sha)

    def test_duplicate_transport_basenames_are_rejected(self):
        duplicate = self.input / "duplicate"
        duplicate.mkdir()
        for path in (self.archive(), self.receipt_path()):
            shutil.copyfile(path, duplicate / path.name)
            with self.assertRaisesRegex(ValueError, "duplicate input name"):
                self.aggregate()
            (duplicate / path.name).unlink()

    def test_duplicate_json_names_are_rejected(self):
        path = self.receipt_path()
        path.write_text(path.read_text().replace('"schema_version": 1', '"schema_version": 1, "schema_version": 1'))
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            self.aggregate()

    def test_receipt_identity_target_smoke_and_archive_mismatches_are_rejected(self):
        original = self.receipt()
        edits = ({"schema_version": 2}, {"schema_version": True}, {"tag": "v9.0.0"},
                 {"version": "9.0.0"}, {"sha": "c" * 40}, {"target": release.TARGETS[1]},
                 {"size": original["size"] + 1}, {"sha256": "0" * 64},
                 {"smoke": {}}, {"smoke": {**release.SMOKE_CHECKS, "versions": 1}},
                 {"archive": "../outside.tar.gz"}, {"archive": "archive\nnewline"},
                 {"executables": {"ergo-node": original["executables"]["ergo-node"]}})
        for edit in edits:
            with self.subTest(edit=edit):
                release.write_json(self.receipt_path(), {**original, **edit})
                with self.assertRaises(ValueError):
                    self.aggregate()
                self.assertFalse(self.output.exists())

    def test_corrupt_archive_is_rejected(self):
        with self.archive().open("ab") as stream:
            stream.write(b"corruption")
        with self.assertRaisesRegex(ValueError, "archive size/sha256 mismatch"):
            self.aggregate()

    def test_internal_binary_hash_mismatch_even_with_updated_archive_hash(self):
        self.rewrite_archive(lambda stage: (stage / "ergo-node").write_bytes(b"tampered"))
        with self.assertRaisesRegex(ValueError, "executable sha256 mismatch"):
            self.aggregate()

    def test_internal_release_metadata_mismatch(self):
        def edit(stage):
            info = json.loads((stage / "release-info.json").read_text())
            info["sha"] = "0" * 40
            release.write_json(stage / "release-info.json", info)
        self.rewrite_archive(edit)
        with self.assertRaisesRegex(ValueError, "release tag/version/sha mismatch"):
            self.aggregate()

    def test_each_required_binary_doc_config_or_license_is_required(self):
        original = self.archive().read_bytes()
        receipt = self.receipt()
        for name in (*release.SUPPORT_FILES, *release.executable_names(self.target), "release-info.json"):
            with self.subTest(name=name):
                self.archive().write_bytes(original)
                release.write_json(self.receipt_path(), receipt)
                self.rewrite_archive(lambda stage: (stage / name).unlink())
                with self.assertRaisesRegex(ValueError, "missing archive contents"):
                    self.aggregate()
                shutil.rmtree(self.root / "rewritten")

    def test_windows_zip_requires_both_exe_names(self):
        target = release.TARGETS[-1]
        self.rewrite_archive(lambda stage: (stage / "ergo-wallet.exe").rename(stage / "ergo-wallet"), target)
        with self.assertRaisesRegex(ValueError, "missing archive contents"):
            self.aggregate()

    def test_unsafe_duplicate_and_symlink_archive_members_are_rejected(self):
        target = release.TARGETS[-1]
        archive = self.archive(target)
        original = archive.read_bytes()
        receipt = self.receipt(target)
        for name in ("../escape", "/absolute", "foo\\bar", "foo\nbar", "C:/absolute", "ergo-node.exe"):
            with self.subTest(name=name):
                archive.write_bytes(original)
                with warnings.catch_warnings(), zipfile.ZipFile(archive, "a") as bundle:
                    warnings.simplefilter("ignore", UserWarning)
                    bundle.writestr(name, b"unsafe")
                release.write_json(self.receipt_path(target), {**receipt, "size": archive.stat().st_size, "sha256": release.checksum(archive)})
                with self.assertRaisesRegex(ValueError, "unsafe archive member|duplicate archive member"):
                    self.aggregate()
        archive.write_bytes(original)
        with zipfile.ZipFile(archive, "a") as bundle:
            member = zipfile.ZipInfo("link")
            member.external_attr = (stat.S_IFLNK | 0o777) << 16
            bundle.writestr(member, b"ergo-node.exe")
        self.mutate_receipt(lambda info: info.update(size=archive.stat().st_size, sha256=release.checksum(archive)), target)
        with self.assertRaisesRegex(ValueError, "member type"):
            self.aggregate()

    def test_tar_symlinks_and_missing_executable_permissions_are_rejected(self):
        # Rebuild fixtures with controlled tar headers while keeping receipt hashes current.
        for mode in ("symlink", "permissions"):
            with self.subTest(mode=mode):
                archive = self.archive()
                original = self.inputs / self.target / "public" / archive.name
                rewritten = self.root / "archive.tar.gz"
                with tarfile.open(original) as source, tarfile.open(rewritten, "w:gz") as dest:
                    for member in source:
                        stream = source.extractfile(member) if member.isfile() else None
                        if member.name == "ergo-node":
                            if mode == "symlink":
                                member.type = tarfile.SYMTYPE
                                member.linkname = "outside"
                                member.size = 0
                                stream = None
                            else:
                                member.mode = 0o644
                        dest.addfile(member, stream)
                        if stream is not None:
                            stream.close()
                shutil.copyfile(rewritten, archive)
                self.mutate_receipt(lambda info: info.update(size=archive.stat().st_size, sha256=release.checksum(archive)))
                with self.assertRaisesRegex(ValueError, "member type|executable permissions"):
                    self.aggregate()

    def test_stale_output_and_overlapping_directories_are_rejected(self):
        self.output.mkdir()
        (self.output / "stale.sha256").write_text("stale")
        with self.assertRaisesRegex(ValueError, "output must be empty"):
            self.aggregate()
        for output in (self.input, self.input / "public", self.root):
            with self.subTest(output=output), self.assertRaisesRegex(ValueError, "must be separate"):
                release.aggregate(self.input, output, self.tag, self.sha)

    def test_transport_symlink_is_rejected(self):
        (self.input / "link").symlink_to(self.archive())
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.aggregate()

    def test_checksum_duplicate_mismatch_format_order_and_self_hash_are_rejected(self):
        self.aggregate()
        path = self.output / "SHA256SUMS"
        original = path.read_bytes()
        edits = (original + original.splitlines(keepends=True)[0], original.replace(b"  ", b" "),
                 original.replace(b"\n", b"\r\n"), b"\n".join(reversed(original.splitlines())) + b"\n",
                 b"0" * 64 + original[64:], original.rstrip(b"\n"),
                 original + b"0" * 64 + b"  SHA256SUMS\n")
        for edit in edits:
            with self.subTest(edit=edit[:70]):
                path.write_bytes(edit)
                with self.assertRaisesRegex(ValueError, "SHA256SUMS mismatch"):
                    release.verify_assets(self.output, self.tag, self.sha)

    def test_manifest_hash_disagreement_is_rejected(self):
        self.aggregate()
        path = self.output / "release.json"
        manifest = json.loads(path.read_text())
        manifest["targets"][self.target]["sha256"] = "0" * 64
        release.write_json(path, manifest)
        with self.assertRaisesRegex(ValueError, "archive size/sha256 mismatch"):
            release.verify_assets(self.output, self.tag, self.sha)

    def test_unexpected_archive_payload_is_rejected(self):
        self.rewrite_archive(lambda stage: (stage / "bare-binary-alias").write_bytes(b"unexpected"))
        with self.assertRaisesRegex(ValueError, "unexpected archive contents"):
            self.aggregate()

    def test_internal_schema_must_be_integer_one(self):
        def edit(stage):
            info = json.loads((stage / "release-info.json").read_text())
            info["schema_version"] = True
            release.write_json(stage / "release-info.json", info)
        self.rewrite_archive(edit)
        with self.assertRaisesRegex(ValueError, "schema_version"):
            self.aggregate()

    def test_published_asset_rerun_guard_accepts_identical_partial_upload(self):
        self.aggregate()
        name = release.archive_name(self.target)
        path = self.output / name
        assets = [{"name": name, "size": path.stat().st_size, "id": 123}]
        def run(command, **kwargs):
            if "stdout" in kwargs:
                kwargs["stdout"].write(path.read_bytes())
                return subprocess.CompletedProcess(command, 0)
            return subprocess.CompletedProcess(command, 0, stdout=json.dumps({"assets": assets}))
        with mock.patch.object(release.subprocess, "run", side_effect=run) as process:
            release.verify_published_assets(self.output, self.tag, "owner/repo")
        self.assertEqual(process.call_count, 2)
        self.assertEqual(process.call_args_list[1].args[0][-2:], ["-H", "Accept: application/octet-stream"])

    def test_published_asset_rerun_guard_rejects_conflicts_and_duplicates(self):
        self.aggregate()
        name = release.archive_name(self.target)
        path = self.output / name
        original = {"name": name, "size": path.stat().st_size, "id": 123}
        for assets in ([{**original, "size": 0}], [{**original, "name": "legacy.sha256"}],
                       [{**original, "id": "../../escape"}], [original, original]):
            def run(command, **kwargs):
                if "stdout" in kwargs:
                    kwargs["stdout"].write(path.read_bytes())
                    return subprocess.CompletedProcess(command, 0)
                return subprocess.CompletedProcess(command, 0, stdout=json.dumps({"assets": assets}))
            with self.subTest(assets=assets), mock.patch.object(release.subprocess, "run", side_effect=run):
                with self.assertRaises(ValueError):
                    release.verify_published_assets(self.output, self.tag, "owner/repo")
        def tampered(command, **kwargs):
            if "stdout" in kwargs:
                kwargs["stdout"].write(b"corrupt published bytes")
                return subprocess.CompletedProcess(command, 0)
            return subprocess.CompletedProcess(command, 0, stdout=json.dumps({"assets": [original]}))
        with mock.patch.object(release.subprocess, "run", side_effect=tampered):
            with self.assertRaisesRegex(ValueError, "published asset differs"):
                release.verify_published_assets(self.output, self.tag, "owner/repo")

    def test_missing_release_is_allowed_but_api_errors_block_publication(self):
        for status in (404, 403, 500):
            result = subprocess.CompletedProcess([], 1, stdout="", stderr=f"gh: error (HTTP {status})")
            with self.subTest(status=status), mock.patch.object(release.subprocess, "run", return_value=result):
                if status == 404:
                    release.verify_published_assets(self.output, self.tag, "owner/repo")
                else:
                    with self.assertRaisesRegex(RuntimeError, "could not inspect"):
                        release.verify_published_assets(self.output, self.tag, "owner/repo")

    def test_failed_smoke_never_issues_receipt(self):
        for failure in ("version", "node", "walletd"):
            output = self.root / failure
            run = self.run_binary if failure in ("node", "walletd") else lambda *a, **kw: subprocess.CompletedProcess(a, 0, stdout="wrong version")
            with mock.patch.object(release, "git", side_effect=self.fixture_git), \
                 mock.patch.object(release.subprocess, "run", side_effect=run), \
                 mock.patch.object(release, "smoke_node", side_effect=RuntimeError("failed node smoke") if failure == "node" else self.smoke_node), \
                 mock.patch.object(release, "smoke_walletd", side_effect=RuntimeError("failed walletd smoke")):
                with self.assertRaises(RuntimeError):
                    release.package(self.target, self.binaries, output, tag=self.tag, sha=self.sha)
            self.assertEqual(list((output / "internal").iterdir()), [])

    def test_package_rejects_wrong_tag_sha_and_missing_input_binary(self):
        for args in ({"tag": "v9.0.0"}, {"sha": "a" * 40}):
            with mock.patch.object(release, "git", side_effect=self.fixture_git), self.assertRaises(ValueError):
                release.package(self.target, self.binaries, self.output, **args)
        missing = self.root / "missing-binaries"
        missing.mkdir()
        shutil.copyfile(self.binaries / "ergo-node", missing / "ergo-node")
        with mock.patch.object(release, "git", side_effect=self.fixture_git), self.assertRaises(FileNotFoundError):
            release.package(self.target, missing, self.output)


if __name__ == "__main__":
    unittest.main()
