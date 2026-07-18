#!/usr/bin/env python3
"""Exhaustive structural and release validation for SecHub/Data."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import unquote

import yaml


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_HEADINGS = [
    "1. Mục tiêu học tập",
    "2. Kiến thức cần có",
    "3. Kiến thức nền tảng",
    "4. Mô tả và nguyên nhân gốc",
    "5. Mô hình đe dọa và điều kiện khai thác",
    "6. Cơ chế tấn công",
    "7. Kiểm thử trong lab được ủy quyền",
    "8. Payload và phạm vi áp dụng",
    "9. Code dễ bị lỗi và code an toàn",
    "10. Phát hiện",
    "11. Phòng thủ",
    "12. Retest",
    "13. Sai lầm thường gặp",
    "14. Tóm tắt và checklist",
    "15. Giải thích thuật ngữ",
    "16. Bài liên quan và đọc thêm",
    "17. Tài liệu tham khảo",
]
REQUIRED_METADATA = {
    "schema_version",
    "id",
    "title",
    "slug",
    "level",
    "estimated_minutes",
    "prerequisites",
    "owasp",
    "cwe",
    "content_status",
    "payload_status",
    "last_verified",
}
PAYLOAD_FIELDS = {
    "payload-id",
    "context",
    "prerequisites",
    "encoding",
    "expected-result",
    "risk",
    "runnable",
    "validation",
    "sources",
    "last-verified",
}
PAYLOAD_ANNOTATION_FIELDS = PAYLOAD_FIELDS | {"evidence"}
RISK_VALUES = {"non-destructive", "state-changing", "destructive", "dos", "oob"}
VALIDATION_VALUES = {"static-verified", "lab-verified"}
MOJIBAKE = ("Ã", "â€™", "â€œ", "â€", "ï»¿", "�")
EXTERNAL_RE = re.compile(r"https?://[^\s)>]+")
MARKDOWN_EXTERNAL_RE = re.compile(r"\[[^]]+\]\(https?://[^)]+\)")
INTERNAL_LINK_RE = re.compile(r"\[[^]]+\]\((?!https?://|mailto:|#)([^)]+)\)")
SOURCE_RE = re.compile(r"\[S(\d+)\]")
SOURCE_DEFINITION_RE = re.compile(r"^- \*\*\[S(\d+)\]\*\* ")
COMMENT_RE = re.compile(r"^<!--\s*([a-z-]+):\s*(.*?)\s*-->$")
GENERIC_ANNOTATION_MARKERS = (
    "ngữ cảnh và phiên bản phải khớp fixture local",
    "chỉ chạy trong lab local được ủy quyền; xác nhận input context trước khi dùng",
    "giữ nguyên byte/UTF-8 như block; protocol framing phải được harness tính lại",
    "quan sát khác biệt được mô tả trong bước kiểm thử, không suy diễn từ một phản hồi đơn lẻ",
)
MECHANICAL_LESSON_MARKERS = (
    "**Tài sản:** dữ liệu, chức năng hoặc tài nguyên được mô tả trong bài.",
    "Dữ liệu do actor kiểm soát đi qua trust boundary và được thành phần đích diễn giải theo cách ngoài ý định.",
    "**Setup:** chạy fixture local/disposable, pin phiên bản, nạp dữ liệu giả và bật application/audit log.",
    "Đặt kiểm soát ở trust boundary có thẩm quyền và kiểm tra thất bại theo fail-closed khi phù hợp.",
)
PAYLOAD_LIKE_RE = re.compile(
    r"(?:UNION\s+SELECT|(?:OR|AND)\s+['\"]?1['\"]?\s*=\s*['\"]?1|<script\b|onerror\s*=|"
    r"\.\./\.\.|\bwhoami\b|\b(?:pg_)?sleep\s*\(|\{\{\s*7\s*\*\s*7\s*\}\}|"
    r"<!ENTITY\b|__proto__|\bnc\s+[^\n]*\s-e\b|powershell[^\n]*-enc)",
    re.IGNORECASE,
)
PAYLOAD_STATUS_NONE_RE = re.compile(
    r"(?:role\s*=\s*admin|is[_-]?admin\s*[:=]\s*true|"
    r"https?://(?:localhost|127(?:\.\d{1,3}){3}|10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|"
    r"169\.254\.169\.254)(?::\d+)?(?:[/?:#][^\s`]*)?|"
    r"(?:;|&&|\|\|)\s*(?:sleep|whoami|id|cat|type)\b|"
    r"^\s*(?:GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s+\S+\s+HTTP/1\.[01]\s*$)",
    re.IGNORECASE | re.MULTILINE,
)


@dataclass
class Result:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    payload_ids: dict[str, str] = field(default_factory=dict)
    lesson_ids: dict[str, str] = field(default_factory=dict)

    def error(self, path: Path, message: str) -> None:
        self.errors.append(f"{path.relative_to(ROOT)}: {message}")

    def warn(self, path: Path, message: str) -> None:
        self.warnings.append(f"{path.relative_to(ROOT)}: {message}")


def lesson_paths() -> list[Path]:
    return sorted(ROOT.glob("[0-9][0-9]-*/**/README.md"))


def split_frontmatter(text: str) -> tuple[dict, str]:
    if not text.startswith("---\n"):
        raise ValueError("missing YAML frontmatter")
    end = text.find("\n---\n", 4)
    if end == -1:
        raise ValueError("unclosed YAML frontmatter")
    metadata = yaml.safe_load(text[4:end])
    if not isinstance(metadata, dict):
        raise ValueError("frontmatter is not a mapping")
    return metadata, text[end + 5 :]


def markdown_lines_outside_fences(text: str) -> list[tuple[int, str]]:
    output: list[tuple[int, str]] = []
    in_fence = False
    for number, line in enumerate(text.splitlines(), start=1):
        if re.match(r"^\s*```", line):
            in_fence = not in_fence
            continue
        if not in_fence:
            output.append((number, line))
    return output


def code_fences(text: str) -> list[tuple[int, str, list[str]]]:
    blocks: list[tuple[int, str, list[str]]] = []
    lines = text.splitlines()
    in_fence = False
    start = 0
    language = ""
    body: list[str] = []
    for index, line in enumerate(lines):
        if not in_fence and re.match(r"^\s*```", line):
            in_fence = True
            start = index
            language = line.strip()[3:].strip()
            body = []
            continue
        if in_fence and re.match(r"^\s*```\s*$", line):
            blocks.append((start, language, body))
            in_fence = False
            continue
        if in_fence:
            body.append(line)
    if in_fence:
        raise ValueError(f"unclosed code fence at line {start + 1}")
    return blocks


def section_text(body: str, number: int) -> str:
    start_match = re.search(rf"(?m)^## {number}\. .+$", body)
    if not start_match:
        return ""
    next_match = re.search(rf"(?m)^## {number + 1}\. .+$", body[start_match.end() :]) if number < 17 else None
    end = start_match.end() + next_match.start() if next_match else len(body)
    return body[start_match.end() : end]


def parse_annotations(lines: list[str], start_index: int) -> dict[str, str]:
    fields: dict[str, str] = {}
    index = start_index - 1
    while index >= 0 and lines[index].strip().startswith("<!--"):
        match = COMMENT_RE.fullmatch(lines[index].strip())
        if match:
            fields[match.group(1)] = match.group(2)
        index -= 1
    return fields


def evidence_node_exists(evidence_path: Path, evidence_node: str) -> bool:
    """Return whether a Python or JavaScript test helper names the evidence node."""
    test_name = evidence_node.rsplit(".", 1)[-1]
    evidence_text = evidence_path.read_text(encoding="utf-8")
    patterns = (
        rf"(?m)^\s*(?:async\s+)?def\s+{re.escape(test_name)}\b",
        rf"(?m)^\s*(?:export\s+)?(?:async\s+)?function\s+{re.escape(test_name)}\b",
    )
    return any(re.search(pattern, evidence_text) for pattern in patterns)


def validate_annotation_bindings(path: Path, text: str, result: Result) -> None:
    """Require each payload annotation group to bind to the next code fence."""
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        match = COMMENT_RE.fullmatch(lines[index].strip())
        if not match or match.group(1) not in PAYLOAD_ANNOTATION_FIELDS:
            index += 1
            continue

        start = index
        fields: set[str] = set()
        while index < len(lines):
            annotation = COMMENT_RE.fullmatch(lines[index].strip())
            if not annotation or annotation.group(1) not in PAYLOAD_ANNOTATION_FIELDS:
                break
            fields.add(annotation.group(1))
            index += 1

        if "payload-id" not in fields:
            result.error(path, f"payload annotation group at line {start + 1} has no payload-id")
        if index >= len(lines) or not re.match(r"^\s*```", lines[index]):
            result.error(
                path,
                f"payload annotation group at line {start + 1} must be immediately followed by a code fence",
            )


def validate_payload_blocks(
    path: Path,
    text: str,
    result: Result,
    source_ids: set[str],
    release: bool = False,
) -> int:
    try:
        blocks = code_fences(text)
    except ValueError as exc:
        result.error(path, str(exc))
        return 0
    lines = text.splitlines()
    count = 0
    for start, _language, _body in blocks:
        fields = parse_annotations(lines, start)
        if not fields:
            continue
        count += 1
        missing = sorted(PAYLOAD_FIELDS - fields.keys())
        if missing:
            result.error(path, f"payload at line {start + 1} missing fields: {', '.join(missing)}")
            continue
        payload_id = fields["payload-id"]
        if payload_id in result.payload_ids:
            result.error(path, f"duplicate payload-id {payload_id}; first seen in {result.payload_ids[payload_id]}")
        else:
            result.payload_ids[payload_id] = str(path.relative_to(ROOT))
        if fields["risk"] not in RISK_VALUES:
            result.error(path, f"payload {payload_id} has invalid risk {fields['risk']}")
        if fields["validation"] not in VALIDATION_VALUES:
            result.error(path, f"payload {payload_id} has invalid validation {fields['validation']}")
        if fields["validation"] == "lab-verified":
            evidence = fields.get("evidence")
            if not evidence:
                result.error(path, f"payload {payload_id} is lab-verified but has no evidence")
            else:
                evidence_file, separator, evidence_node = evidence.partition("::")
                evidence_path = (ROOT / evidence_file).resolve()
                try:
                    evidence_path.relative_to(ROOT)
                except ValueError:
                    result.error(path, f"payload {payload_id} evidence escapes repository: {evidence}")
                    continue
                if not evidence_path.exists():
                    result.error(path, f"payload {payload_id} evidence path does not exist: {evidence}")
                elif not separator or not evidence_node:
                    result.error(path, f"payload {payload_id} evidence must identify a test node with ::")
                else:
                    if not evidence_node_exists(evidence_path, evidence_node):
                        result.error(path, f"payload {payload_id} evidence test node was not found: {evidence}")
        if fields["runnable"] not in {"true", "false"}:
            result.error(path, f"payload {payload_id} runnable must be true or false")
        for field in ("context", "prerequisites", "encoding", "expected-result", "sources"):
            if not fields.get(field, "").strip():
                result.error(path, f"payload {payload_id} has an empty {field}")
        try:
            payload_date = dt.date.fromisoformat(fields["last-verified"])
            if payload_date > dt.date.today():
                result.error(path, f"payload {payload_id} last-verified cannot be in the future")
        except ValueError:
            result.error(path, f"payload {payload_id} last-verified must be an ISO date")
        if release:
            generic = sorted(
                field
                for field in ("context", "prerequisites", "encoding", "expected-result")
                if any(marker in fields.get(field, "") for marker in GENERIC_ANNOTATION_MARKERS)
            )
            if generic:
                result.error(
                    path,
                    f"payload {payload_id} still has mechanical placeholder fields: {', '.join(generic)}",
                )
        for source in (item.strip() for item in fields["sources"].split(",")):
            if source and source not in source_ids:
                result.error(path, f"payload {payload_id} refers to undefined source {source}")
    return count


def validate_internal_links(path: Path, text: str, result: Result) -> None:
    outside = "\n".join(line for _, line in markdown_lines_outside_fences(text))
    for match in INTERNAL_LINK_RE.finditer(outside):
        raw = unquote(match.group(1).split("#", 1)[0])
        if not raw:
            continue
        target = (path.parent / raw).resolve()
        if not target.exists():
            result.error(path, f"broken internal link: {match.group(1)}")


def load_cwe_catalog() -> dict[str, dict]:
    path = ROOT / "data" / "cwe-catalog.json"
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    return data.get("weaknesses", {})


def load_owasp_catalog() -> dict:
    path = ROOT / "data" / "owasp-top10-2025-cwe-map.json"
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def load_owasp_api_catalog() -> dict:
    path = ROOT / "data" / "owasp-api-top10-2023.json"
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def validate_lesson(
    path: Path,
    result: Result,
    cwe_catalog: dict[str, str],
    owasp_catalog: dict,
    owasp_api_catalog: dict,
    release: bool,
) -> None:
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError) as exc:
        result.error(path, f"not valid UTF-8: {exc}")
        return
    for marker in MOJIBAKE:
        if marker in text:
            result.error(path, f"possible mojibake marker {marker!r}")

    try:
        metadata, body = split_frontmatter(text)
    except (ValueError, yaml.YAMLError) as exc:
        result.error(path, str(exc))
        return

    missing = sorted(REQUIRED_METADATA - metadata.keys())
    extra = sorted(metadata.keys() - REQUIRED_METADATA)
    if missing:
        result.error(path, f"metadata missing: {', '.join(missing)}")
    if extra:
        result.error(path, f"metadata has unsupported keys: {', '.join(extra)}")
    if metadata.get("schema_version") != 1:
        result.error(path, "schema_version must be 1")
    if metadata.get("level") not in {"beginner", "intermediate", "advanced"}:
        result.error(path, "invalid level")
    if metadata.get("content_status") not in {"draft", "technical-review", "verified"}:
        result.error(path, "invalid content_status")
    if metadata.get("payload_status") not in {"none", "static-verified", "lab-verified"}:
        result.error(path, "invalid payload_status")
    last_verified = metadata.get("last_verified")
    if metadata.get("content_status") == "verified":
        try:
            if isinstance(last_verified, dt.date):
                verified_date = last_verified
            else:
                verified_date = dt.date.fromisoformat(str(last_verified))
            if verified_date > dt.date.today():
                result.error(path, "last_verified cannot be in the future")
        except ValueError:
            result.error(path, "verified lesson requires an ISO last_verified date")
    elif last_verified is not None:
        result.error(path, "unverified lesson must keep last_verified: null")
    if release and metadata.get("content_status") != "verified":
        result.error(path, "release requires content_status: verified")
    if release and not metadata.get("last_verified"):
        result.error(path, "release requires last_verified")

    lesson_id = metadata.get("id")
    if not isinstance(lesson_id, str) or not re.fullmatch(r"WEB-A\d{2}-[A-Z0-9-]+", lesson_id):
        result.error(path, "invalid lesson id")
    elif lesson_id in result.lesson_ids:
        result.error(path, f"duplicate lesson id; first seen in {result.lesson_ids[lesson_id]}")
    else:
        result.lesson_ids[lesson_id] = str(path.relative_to(ROOT))

    cwes = metadata.get("cwe")
    if not isinstance(cwes, list):
        result.error(path, "cwe must be a list, including [] when no exact mapping exists")
    else:
        for cwe in cwes:
            if not isinstance(cwe, str) or not re.fullmatch(r"CWE-\d+", cwe):
                result.error(path, f"invalid CWE identifier {cwe!r}")
            elif cwe_catalog and cwe not in cwe_catalog:
                result.error(path, f"CWE identifier not found in pinned catalog: {cwe}")
            elif cwe_catalog:
                entry = cwe_catalog[cwe]
                if not isinstance(entry, dict) or not entry.get("name"):
                    result.error(path, f"CWE catalog entry lacks official name/status metadata: {cwe}")
                elif entry.get("status") in {"Deprecated", "Obsolete"}:
                    result.error(path, f"CWE mapping uses {entry['status'].lower()} weakness: {cwe} {entry['name']}")

    owasp = metadata.get("owasp")
    if not isinstance(owasp, list):
        result.error(path, "owasp must be a list, including [] when no exact mapping exists")
    elif path.relative_to(ROOT).parts[0].startswith("11-"):
        valid_api_categories = set(owasp_api_catalog.get("categories", {}))
        if not valid_api_categories:
            result.error(path, "pinned OWASP API Security catalog is missing")
        elif not all(item in valid_api_categories for item in owasp):
            result.error(path, f"invalid OWASP API Security mapping: {owasp}")
    elif owasp_catalog and isinstance(cwes, list):
        expected = owasp_catalog.get("topic_overrides", {}).get(metadata.get("slug"))
        if expected is None:
            expected = sorted(
                {
                    category
                    for cwe in cwes
                    for category in owasp_catalog.get("cwe_to_categories", {}).get(cwe, [])
                }
            )
        if owasp != expected:
            result.error(path, f"OWASP mapping {owasp} differs from pinned official CWE mapping {expected}")

    outside = markdown_lines_outside_fences(body)
    h1 = [line[2:].strip() for _, line in outside if line.startswith("# ")]
    h2 = [line[3:].strip() for _, line in outside if line.startswith("## ")]
    if h1 != [metadata.get("title")]:
        result.error(path, "H1 must exactly match metadata title and occur once")
    if h2 != EXPECTED_HEADINGS:
        result.error(path, f"H2 order differs from lesson contract: {h2}")
    first_h2_line = next((number for number, line in outside if line.startswith("## ")), 10**9)
    preface = "\n".join(line for number, line in outside if number < first_h2_line)
    if "[!CAUTION]" not in preface or "ủy quyền" not in preface:
        result.error(path, "authorized-use warning must appear before section 1")

    validate_annotation_bindings(path, body, result)

    section_17 = section_text(body, 17)
    definitions = {match.group(1) for line in section_17.splitlines() if (match := SOURCE_DEFINITION_RE.match(line))}
    for line in section_17.splitlines():
        if SOURCE_DEFINITION_RE.match(line):
            if not EXTERNAL_RE.search(line):
                result.error(path, f"source definition has no external URL: {line}")
            if not re.search(r"truy cập:\s*\d{4}-\d{2}-\d{2}", line):
                result.error(path, f"source definition has no ISO access date: {line}")
            if not any(marker in line for marker in ("phiên bản", "bản hiện hành", "trạng thái", "cập nhật", "BCP ")):
                result.error(path, f"source definition has no version/status note: {line}")
    used = {match.group(1) for match in SOURCE_RE.finditer(body[: body.find("## 17.")])}
    undefined = sorted(used - definitions)
    orphan = sorted(definitions - used)
    if undefined:
        result.error(path, f"undefined source markers: {', '.join('S' + item for item in undefined)}")
    if orphan:
        result.error(path, f"orphan source definitions: {', '.join('S' + item for item in orphan)}")
    if not definitions:
        result.error(path, "section 17 has no source definitions")

    before_16 = body.split("## 16.", 1)[0]
    for number, line in markdown_lines_outside_fences(before_16):
        # Example endpoints in inline code are part of the lesson/payload, not
        # external references. Reference links still belong only in 16-17.
        without_inline_code = re.sub(r"`[^`]*`", "", line)
        if EXTERNAL_RE.search(without_inline_code) or MARKDOWN_EXTERNAL_RE.search(without_inline_code):
            result.error(path, f"external URL before section 16 at body line {number}")

    payload_section = section_text(body, 8)
    payload_lines = payload_section.splitlines()
    for start, _language, _block in code_fences(payload_section):
        if not parse_annotations(payload_lines, start):
            result.error(path, f"unannotated code/payload block in section 8 at section line {start + 1}")
    payload_count = validate_payload_blocks(
        path,
        payload_section,
        result,
        {"S" + item for item in definitions},
        release=release,
    )
    block_validations = [
        parse_annotations(payload_lines, start).get("validation")
        for start, _language, _block in code_fences(payload_section)
        if parse_annotations(payload_lines, start)
    ]
    expected_payload_status = (
        "none"
        if not block_validations
        else "lab-verified"
        if all(item == "lab-verified" for item in block_validations)
        else "static-verified"
    )
    if metadata.get("payload_status") != expected_payload_status:
        result.error(
            path,
            f"payload_status {metadata.get('payload_status')} does not match block evidence {expected_payload_status}",
        )
    if metadata.get("payload_status") == "none":
        for section_line, line in markdown_lines_outside_fences(payload_section):
            if PAYLOAD_LIKE_RE.search(line) or PAYLOAD_STATUS_NONE_RE.search(line):
                result.error(
                    path,
                    "payload_status none contradicts a concrete payload/input "
                    f"in section 8 at section line {section_line}",
                )
                break

    if release:
        for marker in MECHANICAL_LESSON_MARKERS:
            if marker in body:
                result.error(path, f"release lesson still contains mechanical migration template: {marker[:72]}...")
        code_section = section_text(body, 9)
        has_vulnerable = bool(re.search(r"(?i)vulnerable|dễ bị lỗi|không an toàn", code_section))
        has_secure = bool(re.search(r"(?i)secure|an toàn", code_section))
        if not (has_vulnerable and has_secure):
            result.error(path, "release lesson lacks an explicit vulnerable/secure code or configuration pair in section 9")
        misplaced_sections = []
        for section_number in (*range(1, 8), *range(10, 16)):
            section = section_text(body, section_number)
            if PAYLOAD_LIKE_RE.search(section):
                misplaced_sections.append(section_number)
        if misplaced_sections:
            result.error(
                path,
                "payload-like examples must move to annotated section 8; found in sections "
                + ", ".join(map(str, misplaced_sections)),
            )
        # This deliberately errs on the strict side. Reviewers can split prose
        # or attach a precise source marker; generic source dumping is rejected.
        # Sections 7 and 12 describe this repository's local fixture procedure
        # and retest plan. They need concrete setup/evidence, but they are not
        # automatically external technical claims. Requiring a citation solely
        # because those instructions are long encouraged source dumping.
        for section_number in (3, 4, 5, 6, 8, 9, 10, 11, 13, 15):
            section = "\n".join(
                line for _number, line in markdown_lines_outside_fences(section_text(body, section_number))
            )
            paragraphs = re.split(r"\n\s*\n", section)
            for paragraph in paragraphs:
                plain = re.sub(r"[`*_>#-]", "", paragraph).strip()
                if len(plain) >= 120 and not SOURCE_RE.search(paragraph):
                    result.error(path, f"section {section_number} has a security-sensitive paragraph without source marker")
                    break

    validate_internal_links(path, body, result)


def validate_cheatsheets(result: Result, release: bool) -> None:
    index = ROOT / "security_cheatsheet.md"
    if not index.exists():
        result.error(index, "compatibility index is missing")
        return
    text = index.read_text(encoding="utf-8")
    links = re.findall(r"\]\((cheatsheets/[^)]+\.md)\)", text)
    if len(links) != 15 or len(set(links)) != 15:
        result.error(index, f"expected 15 unique chapter links, found {len(set(links))}")
    chapter_paths = sorted((ROOT / "cheatsheets").glob("*.md"))
    if len(chapter_paths) != 15:
        result.error(ROOT / "cheatsheets", f"expected 15 chapter files, found {len(chapter_paths)}")
    for path in chapter_paths:
        chapter = path.read_text(encoding="utf-8")
        validate_annotation_bindings(path, chapter, result)
        reference_heading = "## Tài liệu tham khảo"
        if reference_heading not in chapter:
            result.error(path, "cheatsheet chapter is missing a final Tài liệu tham khảo section")
            source_ids: set[str] = set()
            before_references = chapter
        else:
            before_references, references = chapter.rsplit(reference_heading, 1)
            source_ids = {
                "S" + match.group(1)
                for line in references.splitlines()
                if (match := SOURCE_DEFINITION_RE.match(line))
            }
            if not source_ids:
                result.error(path, "cheatsheet reference section has no source definitions")
            for line in references.splitlines():
                if SOURCE_DEFINITION_RE.match(line):
                    if not EXTERNAL_RE.search(line):
                        result.error(path, f"cheatsheet source definition has no external URL: {line}")
                    if not re.search(r"truy cập:\s*\d{4}-\d{2}-\d{2}", line):
                        result.error(path, f"cheatsheet source definition has no ISO access date: {line}")
            trailing_h2 = [
                line
                for _number, line in markdown_lines_outside_fences(references)
                if line.startswith("## ")
            ]
            if trailing_h2:
                result.error(path, "Tài liệu tham khảo must be the final H2 section")
        for number, line in markdown_lines_outside_fences(before_references):
            without_inline_code = re.sub(r"`[^`]*`", "", line)
            if EXTERNAL_RE.search(without_inline_code) or MARKDOWN_EXTERNAL_RE.search(without_inline_code):
                result.error(path, f"external URL before final reference section at line {number}")
        try:
            blocks = code_fences(chapter)
        except ValueError as exc:
            result.error(path, str(exc))
            continue
        lines = chapter.splitlines()
        for start, _language, _body in blocks:
            if not parse_annotations(lines, start):
                result.error(path, f"unannotated payload/code block at line {start + 1}")
        validate_payload_blocks(path, chapter, result, source_ids, release=release)
        if release and "Trạng thái:" in chapter:
            result.error(path, "release chapter still contains mechanical-migration status")


def validate_governance(result: Result, release: bool) -> None:
    required = [
        "README.md",
        "AUTHORIZED_USE.md",
        "CONTRIBUTING.md",
        "SECURITY.md",
        "CONTENT_PROVENANCE.md",
        "docs/lesson-schema.md",
        "audit/baseline-manifest.tsv",
        "audit/obsidian-source-index.tsv",
        "audit/payload-ledger.json",
        "audit/source-ledger.json",
        "audit/cwe-mapping-ledger.json",
        "audit/release-readiness.md",
        "audit/review-signoff.yml",
        "audit/provenance-decision.yml",
        "audit/external-link-status.json",
        "LICENSE-STATUS.md",
    ]
    for item in required:
        path = ROOT / item
        if not path.exists():
            result.error(path, "required governance/release artifact is missing")
    if release and (ROOT / "LICENSE-STATUS.md").exists():
        text = (ROOT / "LICENSE-STATUS.md").read_text(encoding="utf-8")
        if "BLOCKED" in text:
            result.error(ROOT / "LICENSE-STATUS.md", "license decision is still BLOCKED")
    decision_path = ROOT / "audit" / "provenance-decision.yml"
    if release and decision_path.exists():
        try:
            decision = yaml.safe_load(decision_path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            result.error(decision_path, f"invalid provenance decision: {exc}")
        else:
            rights = decision.get("baseline_rights", {}) if isinstance(decision, dict) else {}
            required_decision = ("spdx_license", "confirmed_by", "confirmed_at")
            if rights.get("status") != "resolved" or any(not rights.get(field) for field in required_decision):
                result.error(decision_path, "baseline rights/license decision is incomplete")
    provenance_path = ROOT / "CONTENT_PROVENANCE.md"
    if release and provenance_path.exists():
        provenance = provenance_path.read_text(encoding="utf-8")
        if "pending-owner-decision" in provenance or re.search(r"\| pending \|$", provenance, re.MULTILINE):
            result.error(provenance_path, "provenance matrix still contains pending rights or technical review")
    link_status_path = ROOT / "audit" / "external-link-status.json"
    if release and link_status_path.exists():
        try:
            link_status = json.loads(link_status_path.read_text(encoding="utf-8"))
            checked_at = dt.datetime.fromisoformat(link_status["checked_at"])
        except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
            result.error(link_status_path, f"invalid external-link ledger: {exc}")
        else:
            age = dt.datetime.now(dt.timezone.utc) - checked_at.astimezone(dt.timezone.utc)
            broken = [item for item in link_status.get("results", []) if not item.get("ok", False)]
            if age > dt.timedelta(hours=24):
                result.error(link_status_path, f"external-link ledger is stale: {age}")
            if broken:
                result.error(link_status_path, f"external-link ledger contains {len(broken)} hard failures")
    payload_ledger_path = ROOT / "audit" / "payload-ledger.json"
    if release and payload_ledger_path.exists():
        try:
            payload_ledger = json.loads(payload_ledger_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            result.error(payload_ledger_path, f"invalid payload ledger: {exc}")
        else:
            if not payload_ledger.get("payload_release_ready", False):
                result.error(
                    payload_ledger_path,
                    f"payload ledger has unresolved blockers: {payload_ledger.get('blockers', [])}",
                )
    source_ledger_path = ROOT / "audit" / "source-ledger.json"
    if release and source_ledger_path.exists():
        try:
            source_ledger = json.loads(source_ledger_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            result.error(source_ledger_path, f"invalid source ledger: {exc}")
        else:
            unclassified = [
                item for item in source_ledger.get("sources", []) if item.get("tier") == "unclassified-review-required"
            ]
            if unclassified:
                result.error(source_ledger_path, f"source ledger has {len(unclassified)} unclassified occurrences")
    signoff_path = ROOT / "audit" / "review-signoff.yml"
    if release and signoff_path.exists():
        try:
            signoff = yaml.safe_load(signoff_path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            result.error(signoff_path, f"invalid review signoff: {exc}")
        else:
            technical = signoff.get("technical_review", {}) if isinstance(signoff, dict) else {}
            language = signoff.get("language_review", {}) if isinstance(signoff, dict) else {}
            expected_lessons = set(result.lesson_ids)
            expected_cheatsheets = {path.name for path in (ROOT / "cheatsheets").glob("*.md")}
            for name, review in (("technical", technical), ("language", language)):
                if review.get("status") != "complete" or not review.get("reviewer") or not review.get("reviewed_at"):
                    result.error(signoff_path, f"{name} review signoff is incomplete")
                if set(review.get("scope", [])) != expected_lessons:
                    result.error(signoff_path, f"{name} review signoff must cover the exact 77 lesson IDs")
                if set(review.get("cheatsheets", [])) != expected_cheatsheets:
                    result.error(signoff_path, f"{name} review signoff must cover the exact 15 cheatsheet filenames")
            if technical.get("reviewer") and technical.get("reviewer") == language.get("reviewer"):
                result.error(signoff_path, "technical and language reviewers must be independent")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release", action="store_true", help="enable public-release gates")
    parser.add_argument("--json", type=Path, help="write machine-readable result")
    args = parser.parse_args()

    result = Result()
    lessons = lesson_paths()
    if len(lessons) != 77:
        result.errors.append(f"repository: expected 77 lessons, found {len(lessons)}")
    cwe_catalog = load_cwe_catalog()
    owasp_catalog = load_owasp_catalog()
    owasp_api_catalog = load_owasp_api_catalog()
    if not cwe_catalog:
        result.errors.append("data/cwe-catalog.json: pinned CWE catalog is missing or empty")
    if not owasp_catalog:
        result.errors.append("data/owasp-top10-2025-cwe-map.json: pinned OWASP mapping is missing or empty")
    if not owasp_api_catalog:
        result.errors.append("data/owasp-api-top10-2023.json: pinned OWASP API mapping is missing or empty")
    for lesson in lessons:
        validate_lesson(lesson, result, cwe_catalog, owasp_catalog, owasp_api_catalog, args.release)
    validate_cheatsheets(result, args.release)
    validate_governance(result, args.release)

    payload = {
        "mode": "release" if args.release else "pr",
        "lessons": len(lessons),
        "lesson_ids": len(result.lesson_ids),
        "payload_ids": len(result.payload_ids),
        "errors": result.errors,
        "warnings": result.warnings,
    }
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: value for key, value in payload.items() if key not in {"errors", "warnings"}}, ensure_ascii=False))
    for message in result.warnings:
        print(f"WARNING {message}")
    for message in result.errors:
        print(f"ERROR {message}")
    return 1 if result.errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
