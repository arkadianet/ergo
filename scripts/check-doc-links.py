#!/usr/bin/env python3
"""Check local Markdown links and repository doc citations using tracked files.

No missing-target allowlist is used. URL schemes, absolute paths and anchor-only
links are outside the relative-file check. Inline code is not Markdown. Fenced
content is checked unless the opening fence immediately follows the explicit
``<!-- doc-links: example -->`` marker (allowing blank lines). Use that marker
only for examples of Markdown syntax or code that resembles a Markdown link.
HTTP endpoints such as /api-docs/... are not repository citations; citations
must name docs/... or <crate>/docs/... at a path boundary. Legacy development-doc
citations are checked too. Code is checked in full, including comments and
string literals, with only URL tokens excluded.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
CODE_SUFFIXES = {".rs", ".py", ".toml", ".yml", ".yaml", ".mjs", ".cjs", ".sh"}
EXAMPLE_MARKER = "<!-- doc-links: example -->"
FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")
SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
URL = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s\"'<>`]+")
DOC_PATH = re.compile(r"(?<![A-Za-z0-9_./-])(?:[A-Za-z0-9_.-]+/)*(?:dev-)?docs/[A-Za-z0-9_./-]+")
DEFINITION = re.compile(r"^ {0,3}\[([^]\n]+)\]:\s*(?:<([^>\n]+)>|(\S+))", re.MULTILINE)


@dataclass(frozen=True)
class Problem:
    source: str
    line: int
    target: str

    def __str__(self) -> str:
        return f"{self.source}:{self.line}: missing target: {self.target}"


def blank(text: str) -> str:
    """Mask syntax without changing line numbers or character positions."""
    return "".join("\n" if char == "\n" else " " for char in text)


def markdown_text(text: str) -> str:
    """Retain prose and non-example fences, masking only explicit examples."""
    output = []
    fence_char = ""
    fence_length = 0
    example = False
    previous = ""
    prose = []

    def flush_prose() -> None:
        chunk = "".join(prose)
        output.append(re.sub(r"(?<!`)(`+)(?!`)([\s\S]*?)(?<!`)\1(?!`)", lambda m: blank(m[0]), chunk))
        prose.clear()

    for line in text.splitlines(keepends=True):
        match = FENCE.match(line)
        if fence_char:
            closing = match and match[1][0] == fence_char and len(match[1]) >= fence_length and not match[2].strip()
            output.append(blank(line) if example or closing else line)
            if closing:
                fence_char = ""
            continue
        if match:
            flush_prose()
            fence_char, fence_length = match[1][0], len(match[1])
            example = previous == EXAMPLE_MARKER
            output.append(blank(line))
        else:
            # Backtick spans are literal text, not links. Fenced text above is
            # deliberately not passed through this inline-code masking step.
            prose.append(line)
        if line.strip():
            previous = line.strip()
    flush_prose()
    return "".join(output)


def label_key(label: str) -> str:
    return " ".join(label.split()).casefold()


def bracket_end(text: str, start: int) -> int | None:
    depth = 1
    i = start + 1
    while i < len(text):
        if text[i] == "\\":
            i += 2
            continue
        if text[i] == "[":
            depth += 1
        elif text[i] == "]":
            depth -= 1
            if not depth:
                return i
        i += 1
    return None


def destination(text: str, start: int) -> tuple[str, int] | None:
    """Read a link destination, including angle paths and balanced parentheses."""
    i = start
    while i < len(text) and text[i].isspace():
        i += 1
    if i == len(text):
        return None
    begin = i
    if text[i] == "<":
        end = text.find(">", i + 1)
        if end < 0:
            return None
        target = text[i + 1:end]
        i = end + 1
    else:
        depth = 0
        while i < len(text):
            char = text[i]
            if char == "\\":
                i += 2
                continue
            if char == "(":
                depth += 1
            elif char == ")":
                if not depth:
                    return text[begin:i], i + 1
                depth -= 1
            elif char.isspace() and not depth:
                break
            i += 1
        target = text[begin:i]
    # Optional link title after the destination; parentheses inside quotes
    # belong to the title, rather than ending the link.
    quote = ""
    while i < len(text):
        char = text[i]
        if char == "\\":
            i += 2
            continue
        if quote:
            if char == quote:
                quote = ""
        elif char in "\"'":
            quote = char
        elif char == ")":
            return target, i + 1
        i += 1
    return None


def markdown_links(text: str) -> list[tuple[int, str]]:
    visible = markdown_text(text)
    definitions = {}
    links = []
    for match in DEFINITION.finditer(visible):
        target = match[2] if match[2] is not None else match[3]
        definitions.setdefault(label_key(match[1]), target)
        links.append((match.start(), target))
    visible = DEFINITION.sub(lambda m: blank(m[0]), visible)
    i = 0
    while i < len(visible):
        if visible[i] == "\\":
            i += 2
            continue
        if visible[i] != "[":
            i += 1
            continue
        end = bracket_end(visible, i)
        if end is None:
            i += 1
            continue
        label = visible[i + 1:end]
        next_pos = end + 1
        # Inline links must have an adjacent opening parenthesis. Reference
        # labels may be separated by whitespace, including a line break.
        if next_pos < len(visible) and visible[next_pos] == "(":
            parsed = destination(visible, next_pos + 1)
            if parsed:
                target, after = parsed
                links.append((i, target))
                i = after
                continue
        while next_pos < len(visible) and visible[next_pos].isspace():
            next_pos += 1
        key = label_key(label)
        after = end + 1
        if next_pos < len(visible) and visible[next_pos] == "[":
            ref_end = bracket_end(visible, next_pos)
            if ref_end is not None:
                ref = visible[next_pos + 1:ref_end]
                key = label_key(ref or label)
                after = ref_end + 1
        if key in definitions:
            links.append((i, definitions[key]))
        i = after
    return [(visible.count("\n", 0, offset) + 1, target) for offset, target in links]


def relative_target(target: str) -> str | None:
    if not target or target.startswith(("#", "/")) or SCHEME.match(target):
        return None
    # A query/fragment is not part of a filename. Decode percent escapes only
    # after splitting, so an encoded # can still belong to a real filename.
    path = unquote(re.split(r"[?#]", target, maxsplit=1)[0])
    path = re.sub(r"\\([!\"#$%&'()*+,\-./:;<=>?@\[\]\\^_`{|}~])", r"\1", path)
    return path or None


def check_file(root: Path, source: str, text: str) -> list[Problem]:
    suffix = Path(source).suffix
    problems = []
    if suffix == ".md":
        for line, target in markdown_links(text):
            path = relative_target(target)
            if path is not None and not (root / source).parent.joinpath(path).exists():
                problems.append(Problem(source, line, target))
    elif suffix in CODE_SUFFIXES:
        visible = URL.sub(lambda m: blank(m[0]), text)
        for match in DOC_PATH.finditer(visible):
            # A sentence's final period is punctuation, not an extension.
            target = match[0].rstrip(".")
            if not (root / target).exists():
                problems.append(Problem(source, visible.count("\n", 0, match.start()) + 1, target))
    return sorted(set(problems), key=lambda p: (p.line, p.target))


def check_repository(root: Path) -> tuple[list[Problem], int]:
    tracked = subprocess.check_output(["git", "ls-files", "-z"], cwd=root).decode("utf-8").split("\0")
    problems = []
    checked = 0
    for source in tracked:
        if Path(source).suffix not in CODE_SUFFIXES | {".md"}:
            continue
        checked += 1
        path = root / source
        if not path.is_file():
            problems.append(Problem(source, 1, source))
            continue
        problems.extend(check_file(root, source, path.read_text(encoding="utf-8")))
    return problems, checked


def main() -> int:
    problems, checked = check_repository(ROOT)
    for problem in problems:
        print(problem, file=sys.stderr)
    if problems:
        print(f"doc links: {len(problems)} missing targets in {checked} tracked files", file=sys.stderr)
        return 1
    print(f"doc links: checked {checked} tracked files; all targets exist")
    return 0


if __name__ == "__main__":
    sys.exit(main())
