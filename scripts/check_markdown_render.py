#!/usr/bin/env python3
"""Parse every repository Markdown file with a CommonMark-compatible parser."""

from __future__ import annotations

import sys
from pathlib import Path

from markdown_it import MarkdownIt


ROOT = Path(__file__).resolve().parents[1]
EXCLUDED_PARTS = {".git", "node_modules", "playwright-report", "test-results"}


def markdown_paths() -> list[Path]:
    return sorted(
        path
        for path in ROOT.rglob("*.md")
        if not any(part in EXCLUDED_PARTS for part in path.relative_to(ROOT).parts)
    )


def fence_error(text: str) -> str | None:
    marker: str | None = None
    start = 0
    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.lstrip()
        if marker is None and (stripped.startswith("```") or stripped.startswith("~~~")):
            marker = stripped[:3]
            start = line_number
        elif marker is not None and stripped.startswith(marker):
            marker = None
    if marker is not None:
        return f"unclosed {marker} fence opened at line {start}"
    return None


def main() -> int:
    parser = MarkdownIt("commonmark", {"html": True})
    errors: list[str] = []
    paths = markdown_paths()

    for path in paths:
        try:
            text = path.read_text(encoding="utf-8")
            problem = fence_error(text)
            if problem:
                errors.append(f"{path.relative_to(ROOT)}: {problem}")
                continue
            parser.parse(text)
        except (OSError, UnicodeError, ValueError) as exc:
            errors.append(f"{path.relative_to(ROOT)}: {exc}")

    for error in errors:
        print(f"ERROR {error}")
    print(f"Markdown files parsed: {len(paths)}; errors: {len(errors)}")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
