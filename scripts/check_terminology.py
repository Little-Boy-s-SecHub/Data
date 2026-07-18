#!/usr/bin/env python3
"""Check UTF-8 normalization and a small canonical security terminology set."""

from __future__ import annotations

import re
import unicodedata
from pathlib import Path

from validate_content import markdown_lines_outside_fences


ROOT = Path(__file__).resolve().parents[1]
EXCLUDED = {".git", "node_modules", "playwright-report", "test-results"}
TERMS = {
    r"\bJavascript\b": "JavaScript",
    r"\bGithub\b": "GitHub",
    r"\bGitlab\b": "GitLab",
    r"\bNodeJS\b|\bNodeJs\b": "Node.js",
    r"\bOauth\b": "OAuth",
    r"(?<!\.)\bJson\b": "JSON",
    r"uỷ quyền": "ủy quyền",
    r"mã hoá": "mã hóa",
}


def markdown_paths() -> list[Path]:
    return sorted(
        path
        for path in ROOT.rglob("*.md")
        if not any(part in EXCLUDED for part in path.relative_to(ROOT).parts)
    )


def main() -> int:
    errors: list[str] = []
    for path in markdown_paths():
        text = path.read_text(encoding="utf-8")
        if unicodedata.normalize("NFC", text) != text:
            errors.append(f"{path.relative_to(ROOT)}: content is not Unicode NFC")
        for line, visible in markdown_lines_outside_fences(text):
            visible = re.sub(r"`[^`]*`", "", visible)
            for pattern, preferred in TERMS.items():
                for match in re.finditer(pattern, visible):
                    errors.append(
                        f"{path.relative_to(ROOT)}:{line}: use {preferred!r} instead of {match.group(0)!r}"
                    )
    for error in errors:
        print(f"ERROR {error}")
    print(f"Terminology check: files={len(markdown_paths())}; errors={len(errors)}")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
