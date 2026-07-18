#!/usr/bin/env python3
"""Split the legacy monolithic cheatsheet into 15 reviewable chapters."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

from migrate_lessons import ROOT, TODAY, annotate_payloads


SOURCE = ROOT / "security_cheatsheet.md"
DESTINATION = ROOT / "cheatsheets"


def normalize_fences(text: str) -> str:
    """Remove accidental indentation from a closing fence only."""
    output: list[str] = []
    in_fence = False
    for line in text.replace("\r\n", "\n").splitlines():
        if not in_fence and re.match(r"^```", line):
            in_fence = True
            output.append(line)
            continue
        if in_fence and re.match(r"^\s+```\s*$", line):
            output.append("```")
            in_fence = False
            continue
        if in_fence and re.match(r"^```\s*$", line):
            in_fence = False
        output.append(line)
    if in_fence:
        raise ValueError("legacy cheatsheet still has an unclosed code fence")
    return "\n".join(output) + "\n"


def split_chapters(text: str) -> list[tuple[int, str, str]]:
    matches = list(re.finditer(r"(?m)^## (\d{1,2})\. (.+)$", text))
    if len(matches) != 15:
        raise ValueError(f"expected 15 chapters, found {len(matches)}")
    chapters: list[tuple[int, str, str]] = []
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        number = int(match.group(1))
        title = match.group(2).strip()
        body = text[match.end() : end].strip()
        chapters.append((number, title, body))
    return chapters


def slugify(title: str) -> str:
    value = title.lower()
    value = re.sub(r"\([^)]*\)", "", value)
    value = re.sub(r"[^a-z0-9]+", "-", value).strip("-")
    return value or "chapter"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()

    normalized = normalize_fences(SOURCE.read_text(encoding="utf-8-sig"))
    chapters = split_chapters(normalized)
    rendered: list[tuple[Path, str, int]] = []
    for number, title, body in chapters:
        prefix = f"CHEAT-{number:02d}"
        annotated, count = annotate_payloads(body, prefix)
        filename = f"{number:02d}-{slugify(title)}.md"
        content = f"""# {number}. {title}

> [!CAUTION]
> Chỉ dùng trong lab local hoặc hệ thống có ủy quyền rõ ràng. Payload có risk `destructive`, `dos` hoặc `oob` phải chạy trong fixture cô lập, có giới hạn tài nguyên và không có outbound network.

> **Trạng thái:** Nội dung đã được tách cơ học ngày {TODAY}. Annotation `static-verified` chưa thay thế technical review hoặc lab evidence theo từng phiên bản.

{annotated}
"""
        rendered.append((DESTINATION / filename, content, count))

    index_rows = [
        "# Cẩm nang tra cứu và kiểm thử lỗ hổng bảo mật",
        "",
        "> [!CAUTION]",
        "> Chỉ thực hành trong lab local hoặc hệ thống có ủy quyền rõ ràng. Xem `AUTHORIZED_USE.md` trước khi dùng payload.",
        "",
        "File nguyên khối trước đây đã được tách để review, kiểm thử và quản lý provenance theo từng chương. Các liên kết cũ tới `security_cheatsheet.md` vẫn mở được tại index này.",
        "",
        "## 15 chương",
        "",
    ]
    for path, content, count in rendered:
        title = content.splitlines()[0][2:]
        index_rows.append(f"- [{title}](cheatsheets/{path.name}) — {count} block cần payload review.")
    index_rows.extend(
        [
            "",
            "## Trạng thái phát hành",
            "",
            "Các chương chưa được coi là public-release-ready cho đến khi payload ledger và release validator đều đạt.",
            "",
        ]
    )

    if args.write:
        DESTINATION.mkdir(parents=True, exist_ok=True)
        for path, content, _ in rendered:
            path.write_text(content, encoding="utf-8", newline="\n")
        SOURCE.write_text("\n".join(index_rows), encoding="utf-8", newline="\n")
    print(f"chapters={len(rendered)} payload_blocks={sum(item[2] for item in rendered)} write={args.write}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
