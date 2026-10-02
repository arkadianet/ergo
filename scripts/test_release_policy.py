"""Regression tests for release provenance and shared engineering gates."""

import importlib.util
from pathlib import Path
import re
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

    def test_unsupported_cargo_fuzz_lock_flag_is_rejected(self):
        for toolchain in ('nightly', '${{ steps.rust.outputs.nightly }}'):
            with self.subTest(toolchain=toolchain):
                self.workflow.write_text(f'run: cargo +{toolchain} fuzz run bounded_evaluator --locked -- -runs=1\n')
                with self.assertRaisesRegex(ValueError, "cargo-fuzz has no --locked"):
                    policy.check_policy(self.root)

    def test_separate_fuzz_workspace_requires_a_lockfile(self):
        fuzz = self.root / "ergo-difftest/fuzz"
        fuzz.mkdir(parents=True)
        (fuzz / "Cargo.toml").write_text('[workspace]\n')
        with self.assertRaisesRegex(ValueError, "own committed Cargo.lock"):
            policy.check_policy(self.root)
        (fuzz / "Cargo.lock").write_text('version = 4\n')
        policy.check_policy(self.root)

    def test_smoke_overrides_preserve_other_config_sections(self):
        text = '[api]\nbind = "old"\ndisabled = false\n[peers]\nknown = ["127.0.0.1:1"]\n'
        result = release.configure_section(text, "api", {"bind": '"127.0.0.1:9099"'})
        self.assertIn('disabled = false', result)
        self.assertIn('[peers]\nknown = ["127.0.0.1:1"]', result)
        self.assertNotIn('"old"', result)
        result = release.configure_section(result, "api.security", {"api_key_hash": '"hash"'})
        self.assertIn('[api.security]\napi_key_hash = "hash"', result)


class PackagedDocumentation(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.stage = Path(self.temp.name)
        self.sha = "b" * 40
        for name in ("README.md", "SECURITY.md", "ARCHITECTURE.md", "CHANGELOG.md",
                     "rust-toolchain.toml", *(f"docs/{doc}" for doc in release.DOCS),
                     "config/ergo-node.toml", "config/ergo-node.toml.example"):
            destination = self.stage / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            if name == "README.md":
                source = release.ROOT / "docs/release-quickstart.md"
            elif name.startswith("config/"):
                source = release.ROOT / "ergo-node" / destination.name
            else:
                source = release.ROOT / name
            shutil.copy2(source, destination)

    def format(self, document, *, extension=""):
        return release.packaged_document((self.stage / document).read_text(encoding="utf-8"), document,
                                         self.stage, self.sha, extension=extension)

    def test_operator_quickstart_uses_archive_contents_on_unix_and_windows(self):
        for extension in ("", ".exe"):
            with self.subTest(extension=extension):
                content = self.format("docs/operating.md", extension=extension)
                self.assertIn(f"./ergo-node{extension} --version", content)
                self.assertIn(f"./ergo-node{extension} --help", content)
                self.assertIn("cp config/ergo-node.toml ./ergo-node.toml", content)
                self.assertIn(f"./ergo-node{extension} --config ./ergo-node.toml --data-dir ../ergo-data", content)
                self.assertNotIn("cargo build", content)
                self.assertNotIn("./target/release/ergo-node", content)
                self.assertIn("## State modes and how to choose", content)
                readme = self.format("README.md", extension=extension)
                self.assertIn(f"./ergo-node{extension} --config", readme)
                self.assertIn(f"./ergo-wallet{extension} --help", readme)

    def test_bundled_links_stay_local_and_source_links_use_exact_revision(self):
        content = self.format("docs/operating.md")
        self.assertIn("](configuration.md#apiscript)", content)
        self.assertIn("](../config/ergo-node.toml.example)", content)
        for path in ("docs/events.md", "docs/operating-mode-evidence.md", "README.md#running"):
            self.assertIn(f"](https://github.com/arkadianet/ergo/blob/{self.sha}/{path})", content)
        self.assertIn(f"](https://github.com/arkadianet/ergo/tree/{self.sha}/ergo-node/src/config/)", content)
        self.assertNotIn("github.com/arkadianet/ergo/tree/main/", content)
        readme = self.format("README.md")
        self.assertIn("](docs/configuration.md#apisecurity)", readme)
        self.assertIn("](docs/operating.md)", readme)

    def test_every_packaged_relative_document_link_has_an_archive_target(self):
        for document in self.stage.rglob("*.md"):
            name = document.relative_to(self.stage).as_posix()
            content = self.format(name)
            prose = re.sub(r"```.*?```|`[^`\n]*`", "", content, flags=re.DOTALL)
            for link in re.findall(r"\]\(([^)\s]+)\)", prose):
                path = link.split("#", 1)[0]
                if not path or ":" in path:
                    continue
                with self.subTest(document=name, link=link):
                    self.assertTrue((document.parent / path).exists())

    def test_code_examples_are_not_interpreted_as_document_links(self):
        content = '`getVar[T](expr)`\n```rust\ngetVar[T](expr)\n```\n'
        self.assertEqual(release.packaged_document(content, "CHANGELOG.md", self.stage, self.sha), content)

    def test_missing_source_reference_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "missing source link target"):
            release.packaged_document("[missing](no-such-evidence.md)", "docs/operating-mode-evidence.md",
                                      self.stage, self.sha)


if __name__ == "__main__":
    unittest.main()
