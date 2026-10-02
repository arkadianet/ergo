"""Regression tests for release provenance and shared engineering gates."""

import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock


def load_script(name):
    path = Path(__file__).with_name(name + ".py")
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


release = load_script("release")
policy = load_script("ci-policy")


class ReleaseProvenance(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "Cargo.toml").write_text('[workspace.package]\nversion = "0.11.0"\n')
        self.git("init", "-q")
        self.git("config", "user.name", "release test")
        self.git("config", "user.email", "release-test@example.invalid")
        self.git("add", "Cargo.toml")
        self.git("commit", "-qm", "release fixture")

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.root, text=True).strip()

    def test_lightweight_and_annotated_tags_resolve_same_commit(self):
        for annotated in (False, True):
            with self.subTest(annotated=annotated):
                if annotated:
                    self.git("tag", "-a", "v0.11.0", "-m", "release")
                else:
                    self.git("tag", "v0.11.0")
                self.assertEqual(release.resolve("v0.11.0", self.root)["sha"], self.git("rev-parse", "HEAD"))
                self.git("tag", "-d", "v0.11.0")

    def test_tag_and_checkout_mismatch_blocks_validation(self):
        self.git("tag", "v0.11.0")
        self.git("commit", "--allow-empty", "-qm", "unvalidated later commit")
        with self.assertRaisesRegex(ValueError, "exact commit"):
            release.resolve("v0.11.0", self.root)

    def test_tag_and_manifest_mismatch_blocks_release(self):
        self.git("tag", "v0.12.0")
        with self.assertRaisesRegex(ValueError, "workspace version"):
            release.resolve("v0.12.0", self.root)

    def test_unsafe_or_malformed_tag_names_are_rejected(self):
        for tag in ("main", "v01.11.0", "v0.11.0/evil", "v0.11.0\nsha=evil", "v0.11.0;echo unsafe"):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                release.validate_tag(tag, "0.11.0")
        release.validate_tag("v0.11.0-rc.1", "0.11.0-rc.1")

    def test_annotated_remote_tag_uses_peeled_commit(self):
        tag_object, commit = "a" * 40, "b" * 40
        output = f"{tag_object}\trefs/tags/v0.11.0\n{commit}\trefs/tags/v0.11.0^{{}}\n"
        self.assertEqual(release.remote_tag_commit(output, "v0.11.0"), commit)

    def test_moved_or_deleted_remote_tag_blocks_publication(self):
        with mock.patch.object(release, "git", return_value=f"{'b' * 40}\trefs/tags/v0.11.0"):
            with self.assertRaisesRegex(ValueError, "moved"):
                release.verify_remote("v0.11.0", "a" * 40)
        with mock.patch.object(release, "git", return_value=""):
            with self.assertRaisesRegex(ValueError, "missing"):
                release.verify_remote("v0.11.0", "a" * 40)


class EngineeringPolicy(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / ".github/workflows").mkdir(parents=True)
        (self.root / "member").mkdir()
        (self.root / "rust-toolchain.toml").write_text('[toolchain]\nchannel = "1.95.0"\n')
        shutil.copy2(policy.ROOT / ".github/ci-tools.toml", self.root / ".github/ci-tools.toml")
        (self.root / "Cargo.toml").write_text('[workspace]\nmembers = ["member"]\n[workspace.package]\nrust-version = "1.95.0"\n')
        (self.root / "member/Cargo.toml").write_text('[package]\nrust-version.workspace = true\n[lints]\nworkspace = true\n')
        self.workflow = self.root / ".github/workflows/test.yml"
        self.workflow.write_text(f'uses: actions/checkout@{"a" * 40}\nrun: cargo test --locked --workspace\n')

    def test_repository_policy_passes(self):
        policy.check_policy()

    def test_manifest_compiler_drift_is_rejected(self):
        path = self.root / "Cargo.toml"
        path.write_text(path.read_text().replace("1.95.0", "1.94.0"))
        with self.assertRaisesRegex(ValueError, "rust-version"):
            policy.check_policy(self.root)

    def test_member_must_inherit_compiler_and_lints(self):
        for value in ('[package]\nrust-version = "1.95.0"\n[lints]\nworkspace = true\n',
                      '[package]\nrust-version.workspace = true\n'):
            with self.subTest(value=value):
                (self.root / "member/Cargo.toml").write_text(value)
                with self.assertRaises(ValueError):
                    policy.check_policy(self.root)

    def test_mutable_action_or_unlocked_cargo_command_fails(self):
        for text in ('uses: actions/checkout@v4\n', 'run: cargo test --workspace\n',
                     'run: cargo nextest run --workspace\n',
                     'run: cargo install cargo-audit --locked\n'):
            with self.subTest(text=text):
                self.workflow.write_text(text)
                with self.assertRaises(ValueError):
                    policy.check_policy(self.root)

    def test_smoke_overrides_preserve_other_config_sections(self):
        text = '[api]\nbind = "old"\ndisabled = false\n[peers]\nknown = ["127.0.0.1:1"]\n'
        result = release.configure_section(text, "api", {"bind": '"127.0.0.1:9099"'})
        self.assertIn('disabled = false', result)
        self.assertIn('[peers]\nknown = ["127.0.0.1:1"]', result)
        self.assertNotIn('"old"', result)
        result = release.configure_section(result, "api.security", {"api_key_hash": '"hash"'})
        self.assertIn('[api.security]\napi_key_hash = "hash"', result)


if __name__ == "__main__":
    unittest.main()
