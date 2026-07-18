#!/usr/bin/env python3
"""Reject long topic prose copied across unrelated lessons.

The lesson contract and authorized-use warning are intentionally consistent.
Technical explanations, detection guidance, retest logic, and mistakes must be
specific enough to the vulnerability that the same long paragraph is not
copied throughout the curriculum.
"""

from __future__ import annotations

import collections
import re
from pathlib import Path

from validate_content import ROOT, markdown_lines_outside_fences, split_frontmatter


MIN_PARAGRAPH_CHARS = 120
MAX_LESSON_REUSE = 3
AUTHORIZED_WARNING_PREFIX = (
    "CAUTION Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng."
)


def normalize(paragraph: str) -> str:
    visible = re.sub(r"[`*_>#\[\]()!-]", "", paragraph)
    return re.sub(r"\s+", " ", visible).strip()


def lesson_paragraphs(path: Path) -> set[str]:
    _metadata, body = split_frontmatter(path.read_text(encoding="utf-8"))
    # Related-reading and reference lists legitimately repeat titles/metadata.
    body = body.split("## 16.", 1)[0]
    visible = "\n".join(line for _number, line in markdown_lines_outside_fences(body))
    paragraphs = {
        normalize(paragraph)
        for paragraph in re.split(r"\n\s*\n", visible)
        if len(normalize(paragraph)) >= MIN_PARAGRAPH_CHARS
    }
    return {
        paragraph
        for paragraph in paragraphs
        if not paragraph.startswith(AUTHORIZED_WARNING_PREFIX)
    }


def main() -> int:
    occurrences: dict[str, list[Path]] = collections.defaultdict(list)
    lessons = sorted(ROOT.glob("[0-9][0-9]-*/**/README.md"))
    for path in lessons:
        for paragraph in lesson_paragraphs(path):
            occurrences[paragraph].append(path)

    errors: list[str] = []
    for paragraph, paths in sorted(
        occurrences.items(), key=lambda item: (-len(item[1]), item[0])
    ):
        if len(paths) <= MAX_LESSON_REUSE:
            continue
        locations = ", ".join(str(path.relative_to(ROOT)) for path in paths[:5])
        suffix = " ..." if len(paths) > 5 else ""
        errors.append(
            f"paragraph reused in {len(paths)} lessons ({locations}{suffix}): "
            f"{paragraph[:180]}"
        )

    for error in errors:
        print(f"ERROR {error}")
    print(
        f"Duplicate prose: lessons={len(lessons)}; "
        f"max_reuse={MAX_LESSON_REUSE}; errors={len(errors)}"
    )
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
