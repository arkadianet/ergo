"""Regression tests for tracked-file documentation link policy."""

import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("check-doc-links.py")
spec = importlib.util.spec_from_file_location("check_doc_links", SCRIPT)
checker = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = checker
spec.loader.exec_module(checker)
DOCS = "docs" + "/"
CRATE_DOCS = "crate/" + DOCS


class LinkChecks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.write(DOCS + "guide.md")
        self.write(CRATE_DOCS + "design.md")
        self.write("space name.md")
        self.write("a(b).md")
        self.write("hash#name.md")

    def write(self, path, text=""):
        file = self.root / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(text, encoding="utf-8")
        return file

    def check(self, text, source="README.md"):
        return checker.check_file(self.root, source, text)

    def test_missing_inline_link_reports_file_line_and_target(self):
        problems = self.check("Text\n[x](missing.md#anchor)\n")
        self.assertEqual(problems, [checker.Problem("README.md", 2, "missing.md#anchor")])

    def test_paths_resolve_relative_to_markdown_file(self):
        self.assertEqual(self.check("[x](guide.md#unchecked-anchor)", DOCS + "index.md"), [])
        self.assertEqual(self.check("[x](../space%20name.md)", DOCS + "index.md"), [])
        self.assertTrue(self.check("[x](guide.md)", "README.md"))

    def test_percent_escapes_angle_paths_and_titles(self):
        text = '[x](space%20name.md "title (text)") [y](<space name.md> \'title\') [z](hash%23name.md)'
        self.assertEqual(self.check(text), [])

    def test_balanced_parentheses_and_escaped_destinations(self):
        self.assertEqual(self.check(r"[x](a(b).md) [y](a\(b\).md)"), [])
        self.assertTrue(self.check("[x](missing(part).md)"))

    def test_images_and_nested_link_labels_are_checked(self):
        self.assertEqual([p.target for p in self.check("![image](missing.png) [a [b]](gone.md)")],
                         ["gone.md", "missing.png"])

    def test_external_absolute_and_anchor_links_are_outside_policy(self):
        self.assertEqual(self.check("[a](#anchor) [b](https://example.invalid/missing.md) "
                                    "[c](mailto:a@example.invalid) [d](//example.invalid/x) "
                                    "[e](/absolute/path.md) [f](data:text/plain,hello)"), [])

    def test_empty_destination_is_current_document(self):
        self.assertEqual(self.check("[x]()"), [])

    def test_reference_full_collapsed_shortcut_and_casefold(self):
        text = "[Full][MY ref] [my ref][] [MY REF]\n[my ref]: missing.md \"title\"\n"
        self.assertEqual(len(self.check(text)), 2)  # one use-line plus definition
        self.assertEqual([line for line, _ in checker.markdown_links(text)], [2, 1, 1, 1])

    def test_unused_reference_definitions_are_checked(self):
        self.assertTrue(self.check("[unused]: <missing file.md>\n"))
        self.assertEqual(self.check("[unused]: <space name.md>\n"), [])

    def test_undefined_reference_is_not_a_file_link(self):
        self.assertEqual(self.check("[undefined] [x][also undefined]"), [])

    def test_inline_code_and_escaped_link_syntax_are_literal(self):
        self.assertEqual(self.check(r"`[x](missing.md)` \[x](missing.md)"), [])
        self.assertEqual(self.check("``text `[x](missing.md)` text``"), [])

    def test_multiline_inline_code_is_literal(self):
        self.assertEqual(self.check("`foo\nDeserializeContext[Boolean](0)`\n[x](missing.md)"),
                         [checker.Problem("README.md", 3, "missing.md")])

    def test_fenced_links_are_checked_without_example_marker(self):
        for delimiter in ("```", "~~~~"):
            with self.subTest(delimiter=delimiter):
                self.assertEqual(self.check(f"{delimiter}markdown\n[x](missing.md)\n{delimiter}\n"),
                                 [checker.Problem("README.md", 2, "missing.md")])
                self.assertTrue(self.check(f"{delimiter}rust\n`[x](missing.md)`\n{delimiter}\n"))

    def test_explicit_example_marker_skips_only_its_fence(self):
        text = (checker.EXAMPLE_MARKER + "\n\n```markdown\n[x](missing.md)\n```\n"
                "[x](gone.md)\n```markdown\n[x](other.md)\n```\n")
        self.assertEqual([(p.line, p.target) for p in self.check(text)], [(6, "gone.md"), (8, "other.md")])

    def test_marker_separated_by_prose_does_not_exempt_fence(self):
        text = checker.EXAMPLE_MARKER + "\nSome prose\n```markdown\n[x](missing.md)\n```"
        self.assertTrue(self.check(text))

    def test_example_marker_is_consumed_by_one_fence(self):
        text = checker.EXAMPLE_MARKER + "\n```markdown\n[x](missing.md)\n```\n```markdown\n[x](gone.md)\n```"
        self.assertEqual(self.check(text), [checker.Problem("README.md", 6, "gone.md")])

    def test_shorter_or_different_fence_does_not_close_example(self):
        text = checker.EXAMPLE_MARKER + "\n````markdown\n```\n~~~\n[x](missing.md)\n````\n[x](gone.md)"
        self.assertEqual(self.check(text), [checker.Problem("README.md", 7, "gone.md")])

    def test_all_required_code_extensions_check_comments_and_strings(self):
        text = f'# see {DOCS}missing.md\nvalue = "{DOCS}guide.md"\n'
        for extension in checker.CODE_SUFFIXES:
            with self.subTest(extension=extension):
                self.assertEqual(self.check(text, "source" + extension),
                                 [checker.Problem("source" + extension, 1, DOCS + "missing.md")])

    def test_code_paths_are_repo_relative_with_crate_prefix(self):
        self.assertEqual(self.check(DOCS + "guide.md and " + CRATE_DOCS + "design.md", "crate/src/lib.rs"), [])
        self.assertTrue(self.check(CRATE_DOCS + "missing.md", "source.rs"))

    def test_code_anchors_and_sentence_punctuation_are_not_filename_parts(self):
        self.assertEqual(self.check(f"{DOCS}guide.md. {DOCS}guide.md#anchor", "source.rs"), [])

    def test_urls_and_api_routes_are_not_repository_citations(self):
        text = f'https://example.invalid/{DOCS}absent.md /api-docs/openapi-rust.json'
        self.assertEqual(self.check(text, "source.rs"), [])
        self.assertTrue(self.check(f"prefix: {DOCS}openapi-rust.json", "source.rs"))

    def test_legacy_development_doc_citations_are_checked(self):
        target = "dev-" + DOCS + "missing.md"
        self.assertEqual(self.check(target, "source.rs"), [checker.Problem("source.rs", 1, target)])

    def test_non_requested_file_extensions_are_ignored(self):
        self.assertEqual(self.check(DOCS + "missing.md", "fixture.json"), [])


class TrackedRepository(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)

    def stage(self, path, content):
        file = self.root / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(content, encoding="utf-8")
        subprocess.run(["git", "add", path], cwd=self.root, check=True)
        return file

    def test_tracked_sources_only_and_new_staged_files_are_checked(self):
        self.stage("tracked.md", "[missing](absent.md)")
        (self.root / "untracked.md").write_text("[missing](another.md)")
        self.stage("settings.yaml", DOCS + "absent.md")
        problems, checked = checker.check_repository(self.root)
        self.assertEqual(checked, 2)
        self.assertEqual({p.source for p in problems}, {"tracked.md", "settings.yaml"})

    def test_deleted_unstaged_source_fails_but_staged_deletion_does_not(self):
        self.stage("tracked.md", "").unlink()
        self.assertTrue(checker.check_repository(self.root)[0])
        subprocess.run(["git", "add", "-u"], cwd=self.root, check=True)
        self.assertEqual(checker.check_repository(self.root), ([], 0))

    def test_cli_status_and_useful_diagnostics(self):
        self.stage("README.md", "[missing](absent.md)")
        script = self.root / "scripts/check-doc-links.py"
        script.parent.mkdir()
        script.write_text(SCRIPT.read_text(encoding="utf-8"), encoding="utf-8")
        result = subprocess.run([sys.executable, str(script)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("README.md:1: missing target: absent.md", result.stderr)
        (self.root / "absent.md").write_text("")
        result = subprocess.run([sys.executable, str(script)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn("all targets exist", result.stdout)


if __name__ == "__main__":
    unittest.main()
