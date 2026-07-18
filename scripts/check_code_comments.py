#!/usr/bin/env python3
"""Reject Vietnamese prose in fenced-code comments.

Lesson prose is Vietnamese, while comments embedded in code examples must be
English.  This checker intentionally inspects only fenced code blocks so that
normal lesson text and Markdown annotations are unaffected.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VIETNAMESE = re.compile(
    r"[àáạảãâầấậẩẫăằắặẳẵèéẹẻẽêềếệểễìíịỉĩ"
    r"òóọỏõôồốộổỗơờớợởỡùúụủũưừứựửữỳýỵỷỹđ"
    r"ÀÁẠẢÃÂẦẤẬẨẪĂẰẮẶẲẴÈÉẸẺẼÊỀẾỆỂỄÌÍỊỈĨ"
    r"ÒÓỌỎÕÔỒỐỘỔỖƠỜỚỢỞỠÙÚỤỦŨƯỪỨỰỬỮỲÝỴỶỸĐ]"
)
FENCE = re.compile(r"^\s*```(?P<language>[^`]*)$")
COMMENT_START = re.compile(r"^\s*(?:#|//|/\*|\*|--|<!--|;|%)")
INLINE_COMMENT = re.compile(r"(?:\s#\s|(?<!:)//|\s--\s|/\*|<!--)")


def markdown_paths() -> list[Path]:
    lessons = ROOT.glob("[0-9][0-9]-*/**/README.md")
    chapters = (ROOT / "cheatsheets").glob("*.md")
    return sorted([*lessons, *chapters])


def violations(path: Path) -> list[tuple[int, str]]:
    findings: list[tuple[int, str]] = []
    in_fence = False
    in_block_comment = False

    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if FENCE.match(line):
            in_fence = not in_fence
            in_block_comment = False
            continue
        if not in_fence:
            continue

        stripped = line.strip()
        is_comment = in_block_comment or bool(COMMENT_START.match(line)) or bool(INLINE_COMMENT.search(line))
        if VIETNAMESE.search(line) and is_comment:
            findings.append((line_number, stripped))

        if "/*" in line and "*/" not in line.split("/*", 1)[1]:
            in_block_comment = True
        if "<!--" in line and "-->" not in line.split("<!--", 1)[1]:
            in_block_comment = True
        if in_block_comment and ("*/" in line or "-->" in line):
            in_block_comment = False

    return findings


def main() -> int:
    all_findings: list[tuple[Path, int, str]] = []
    for path in markdown_paths():
        all_findings.extend((path, line, text) for line, text in violations(path))

    if all_findings:
        for path, line, comment in all_findings:
            print(f"ERROR {path.relative_to(ROOT)}:{line}: Vietnamese code comment: {comment}")
        print(f"Vietnamese code comments: {len(all_findings)}")
        return 1

    print(f"Vietnamese code comments: 0 (files={len(markdown_paths())})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
