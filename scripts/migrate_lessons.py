#!/usr/bin/env python3
"""Migrate the original SecHub lessons to schema version 1.

This is intentionally a mechanical migration. It never promotes a lesson to
``verified``. Technical and language review must happen after the migration.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TODAY = "2026-07-17"

ORIGINAL_HEADINGS = (
    "Kiến thức Nền tảng",
    "Mô tả lỗ hổng",
    "Cơ chế tấn công",
    "Biện pháp phòng thủ",
    "Code Example",
    "Xem thêm",
    "Nguồn tham khảo",
    "Giải thích thuật ngữ",
)

OWASP_BY_GROUP = {
    "01": "A01:2025",
    "02": "A02:2025",
    "03": "A03:2025",
    "04": "A04:2025",
    "05": "A05:2025",
    "06": "A06:2025",
    "07": "A07:2025",
    "08": "A08:2025",
    "09": "A09:2025",
    "10": "A10:2025",
}

API_OWASP = {
    "api-rate-limiting": ["API4:2023"],
    "graphql-vulnerabilities": ["API1:2023", "API3:2023", "API4:2023", "API8:2023"],
    "shadow-apis": ["API9:2023"],
}

# Corrections that are safe to apply mechanically because the old mapping is
# demonstrably about another root cause. An empty list is deliberate: broad
# topics do not always have one precise CWE.
CWE_OVERRIDES = {
    "business-logic-vulnerabilities": [],
    "dns-poisoning": ["CWE-345"],
    "lax-security-settings": [],
    "regex-injection": ["CWE-1333"],
    "session-hijacking": [],
    "subdomain-squatting": [],
}

ADVANCED = {
    "buffer-overflows",
    "http-request-smuggling",
    "insecure-deserialization",
    "prototype-pollution",
    "ssti",
    "xml-bombs",
}

BEGINNER = {
    "broken-access-control",
    "clickjacking",
    "csrf",
    "directory-traversal",
    "idor",
    "open-redirects",
    "sql-injection",
    "xss",
}

PRIMARY_CONTROL = {
    "01": "Thực thi phân quyền phía máy chủ trên từng đối tượng và hành động trước khi truy cập dữ liệu.",
    "02": "Dùng cấu hình an toàn theo mặc định, allowlist rõ ràng và kiểm tra cấu hình trong quy trình triển khai.",
    "03": "Xác minh nguồn gốc, tính toàn vẹn và vòng đời của mọi thành phần trong chuỗi cung ứng.",
    "04": "Dùng giao thức và primitive mật mã hiện hành với quản lý khóa, entropy và xác thực phù hợp.",
    "05": "Tách dữ liệu khỏi cú pháp bằng API có tham số hoặc encoding theo đúng output context.",
    "06": "Thiết kế invariant bảo mật và thực thi invariant ở phía máy chủ cho mọi luồng nghiệp vụ.",
    "07": "Ràng buộc danh tính, phiên và bước xác thực vào vòng đời phía máy chủ với cơ chế chống phát lại.",
    "08": "Xác minh tính toàn vẹn và tính xác thực trước khi diễn giải dữ liệu hoặc chuyển tiếp request.",
    "09": "Ghi nhận sự kiện có ngữ cảnh, bảo vệ log và tạo cảnh báo có người chịu trách nhiệm xử lý.",
    "10": "Giới hạn tài nguyên, fail safely và xử lý mọi trạng thái ngoại lệ có thể đạt tới.",
    "11": "Áp dụng kiểm soát ở cấp đối tượng, thuộc tính, chức năng và mức tiêu thụ tài nguyên của API.",
}


def lesson_paths() -> list[Path]:
    return sorted(ROOT.glob("[0-9][0-9]-*/**/README.md"))


def parse_original(text: str, path: Path) -> tuple[str, dict[str, str], list[str]]:
    lines = text.replace("\r\n", "\n").splitlines()
    if not lines or not lines[0].startswith("# "):
        raise ValueError(f"{path}: missing original title")
    title = lines[0][2:].strip()
    cwes: list[str] = []
    for line in lines[:6]:
        cwes.extend(re.findall(r"CWE-\d+", line))

    sections: dict[str, list[str]] = {name: [] for name in ORIGINAL_HEADINGS}
    current: str | None = None
    for line in lines[1:]:
        match = re.fullmatch(r"## (.+)", line.strip())
        if match and match.group(1) in sections:
            current = match.group(1)
            continue
        if current is not None:
            sections[current].append(line)

    missing = [name for name, body in sections.items() if not any(item.strip() for item in body)]
    if missing:
        raise ValueError(f"{path}: empty or missing sections: {', '.join(missing)}")
    return title, {name: "\n".join(body).strip() for name, body in sections.items()}, list(dict.fromkeys(cwes))


def yaml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def frontmatter(path: Path, title: str, cwes: list[str], has_payloads: bool) -> str:
    relative = path.relative_to(ROOT)
    group = relative.parts[0][:2]
    lesson_parts = list(relative.parts[1:-1])
    slug = "-".join(lesson_parts)
    leaf = lesson_parts[-1]
    cwes = CWE_OVERRIDES.get(leaf, cwes)
    owasp = API_OWASP.get(leaf, ["API:2023"]) if group == "11" else [OWASP_BY_GROUP[group]]
    level = "advanced" if leaf in ADVANCED else "beginner" if leaf in BEGINNER else "intermediate"
    estimated = 35 if level == "beginner" else 50 if level == "intermediate" else 65
    lesson_id = f"WEB-A{group}-{'-'.join(part.upper() for part in lesson_parts)}"
    prerequisites = ["http-fundamentals", "authorized-security-testing"]
    if group in {"01", "07"}:
        prerequisites.append("authentication-vs-authorization")

    rows = [
        "---",
        "schema_version: 1",
        f"id: {lesson_id}",
        f"title: {yaml_string(title)}",
        f"slug: {slug}",
        f"level: {level}",
        f"estimated_minutes: {estimated}",
        "prerequisites:",
        *[f"  - {item}" for item in prerequisites],
        "owasp:",
        *[f"  - {item}" for item in owasp],
        "cwe:",
        *([f"  - {item}" for item in cwes] if cwes else ["  []"]),
        "content_status: technical-review",
        f"payload_status: {'static-verified' if has_payloads else 'none'}",
        "last_verified: null",
        "---",
    ]
    return "\n".join(rows)


def payload_risk(code: str) -> str:
    lowered = code.lower()
    if re.search(r"drop\s+table|rm\s+-rf|delete\s+from|unlink\(|os\.remove", lowered):
        return "destructive"
    if re.search(r"billion laughs|fork\s*bomb|while\s*\(true|pg_sleep|sleep\(|benchmark\(", lowered):
        return "dos"
    if re.search(r"attacker\.(?:com|net)|collaborator|callback|reverse.shell|nc\s+.*-e", lowered):
        return "oob"
    if re.search(r"\b(?:post|put|patch|delete)\s+/|\b(?:update|insert)\s+", lowered):
        return "state-changing"
    return "non-destructive"


def payload_context(language: str, code: str) -> str:
    language = language or "text"
    lowered = code.lower()
    if language == "http":
        version = "HTTP/1.1" if "http/1.1" in lowered else "HTTP fixture"
        return f"{version}; request minh họa trong lab local"
    if language in {"javascript", "html"}:
        return f"{language}; Chromium được pin trong browser harness local"
    if language in {"python", "java", "php", "ruby", "c", "csharp"}:
        return f"{language}; phiên bản runtime phải được pin trong fixture trước khi chạy"
    return f"{language}; ngữ cảnh và phiên bản phải khớp fixture local"


def annotate_payloads(markdown: str, prefix: str, source_id: str = "S1") -> tuple[str, int]:
    lines = markdown.splitlines()
    output: list[str] = []
    in_fence = False
    fence_start = 0
    opening = ""
    count = 0

    # First collect complete blocks so annotations can describe the block body.
    blocks: dict[int, tuple[str, str]] = {}
    for index, line in enumerate(lines):
        if not in_fence and re.match(r"^\s*```", line):
            in_fence = True
            fence_start = index
            opening = line.strip()[3:].strip()
        elif in_fence and re.match(r"^\s*```\s*$", line):
            body = "\n".join(lines[fence_start + 1 : index])
            blocks[fence_start] = (opening, body)
            in_fence = False
    if in_fence:
        raise ValueError(f"unclosed fence in {prefix}")

    for index, line in enumerate(lines):
        block = blocks.get(index)
        if block:
            language, body = block
            count += 1
            payload_id = f"{prefix}-{count:03d}"
            output.extend(
                [
                    f"<!-- payload-id: {payload_id} -->",
                    f"<!-- context: {payload_context(language, body)} -->",
                    "<!-- prerequisites: chỉ chạy trong lab local được ủy quyền; xác nhận input context trước khi dùng -->",
                    "<!-- encoding: giữ nguyên byte/UTF-8 như block; protocol framing phải được harness tính lại -->",
                    "<!-- expected-result: quan sát khác biệt được mô tả trong bước kiểm thử, không suy diễn từ một phản hồi đơn lẻ -->",
                    f"<!-- risk: {payload_risk(body)} -->",
                    "<!-- runnable: false -->",
                    "<!-- validation: static-verified -->",
                    f"<!-- sources: {source_id} -->",
                    f"<!-- last-verified: {TODAY} -->",
                ]
            )
        output.append(line)
    return "\n".join(output), count


def extract_sources(markdown: str, cwes: list[str]) -> list[tuple[str, str]]:
    sources: list[tuple[str, str]] = []
    for line in markdown.splitlines():
        urls = re.findall(r"https?://[^\s)>]+", line)
        for url in urls:
            url = url.rstrip(".,;:")
            label = re.sub(r"https?://[^\s)>]+", "", line)
            label = re.sub(r"^\s*[-*]\s*", "", label).strip(" :-") or "Nguồn gốc"
            sources.append((label, url))

    sources.append(("OWASP Top 10:2025", "https://owasp.org/Top10/2025/"))
    for cwe in cwes:
        number = cwe.split("-", 1)[1]
        sources.append((cwe, f"https://cwe.mitre.org/data/definitions/{number}.html"))

    deduplicated: list[tuple[str, str]] = []
    seen: set[str] = set()
    for label, url in sources:
        normalized = url.rstrip("/").lower()
        if normalized in seen:
            continue
        seen.add(normalized)
        deduplicated.append((label, url))
    return deduplicated


def reference_section(sources: list[tuple[str, str]]) -> str:
    rows = []
    for index, (label, url) in enumerate(sources, start=1):
        rows.append(
            f"- **[S{index}]** {label}. {url} — phiên bản/trạng thái: bản hiện hành; "
            f"truy cập: {TODAY}."
        )
    return "\n".join(rows)


def source_review_note(sources: list[tuple[str, str]]) -> str:
    markers = ", ".join(f"[S{index}]" for index in range(1, len(sources) + 1))
    return (
        "> **Gate kỹ thuật:** các nguồn cần được đối chiếu trực tiếp cho từng claim trước khi đổi "
        f"`content_status` sang `verified`: {markers}."
    )


def migrate(path: Path) -> str:
    text = path.read_text(encoding="utf-8-sig")
    title, sections, cwes = parse_original(text, path)
    relative = path.relative_to(ROOT)
    group = relative.parts[0][:2]
    leaf = relative.parent.name
    cwes = CWE_OVERRIDES.get(leaf, cwes)
    sources = extract_sources(sections["Nguồn tham khảo"], cwes)

    payload_prefix = f"WEB-A{group}-{'-'.join(part.upper() for part in relative.parts[1:-1])}"
    payloads, payload_count = annotate_payloads(sections["Cơ chế tấn công"], payload_prefix)

    warning = (
        "> [!CAUTION]\n"
        "> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, "
        "fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật."
    )

    goal = f"""Sau bài học, bạn có thể:

- Giải thích {title} bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case."""

    prerequisite = """- Nắm luồng HTTP request/response và cách ứng dụng xử lý input qua các trust boundary.
- Phân biệt authentication, authorization và validation.
- Biết đọc code/configuration trong ngôn ngữ hoặc framework xuất hiện ở ví dụ.
- Có lab local cô lập, dữ liệu giả, log quan sát được và quyền kiểm thử rõ ràng."""

    root_cause = sections["Mô tả lỗ hổng"] + "\n\n" + source_review_note(sources)
    if not cwes:
        root_cause += (
            "\n\n> **Lưu ý mapping:** chủ đề này không có một CWE duy nhất đủ chính xác; "
            "không gán CWE chỉ vì tên hoặc hậu quả có vẻ tương tự."
        )

    threat_model = f"""- **Tài sản:** dữ liệu, chức năng hoặc tài nguyên được mô tả trong bài.
- **Trust boundary:** nơi input do client hoặc thành phần kém tin cậy đi vào xử lý phía server/client.
- **Actor:** người dùng chưa đăng nhập, người dùng hợp lệ hoặc thành phần trung gian tùy use case.
- **Điều kiện cần:** actor điều khiển được input liên quan; đường xử lý dễ lỗi thực sự được gọi; và kiểm soát gốc bị thiếu hoặc sai.
- **Điều kiện môi trường:** phải ghi rõ trạng thái đăng nhập/role, browser/proxy, protocol, framework và phiên bản fixture trước khi kết luận.

Không suy ra khả năng khai thác chỉ từ payload hoặc status code; phải quan sát tác động tại trust boundary và log tương ứng. [S1]"""

    mechanism = f"""Dữ liệu do actor kiểm soát đi qua trust boundary và được thành phần đích diễn giải theo cách ngoài ý định. Chuỗi kiểm thử phải chứng minh lần lượt: input đến được sink, kiểm soát gốc không chặn, và tác động quan sát được thuộc đúng phiên/người dùng/tài nguyên. Chi tiết cụ thể và giới hạn phụ thuộc công nghệ được ghi cùng payload ở mục 8. [S1]"""

    lab = """1. **Setup:** chạy fixture local/disposable, pin phiên bản, nạp dữ liệu giả và bật application/audit log.
2. **Input:** bắt đầu bằng một request hợp lệ làm baseline; chỉ dùng payload `non-destructive` phù hợp context.
3. **Thao tác:** thay đổi một biến mỗi lần, ghi lại raw request/response, trạng thái ứng dụng và log.
4. **Expected result:** positive case chứng minh hành vi lỗi; negative case không tạo tác động; boundary case được xử lý an toàn.
5. **Cleanup:** dừng fixture, xóa dữ liệu giả/callback local và khôi phục snapshot nếu có thay đổi trạng thái.
6. **Giới hạn an toàn:** payload `destructive`, `dos` hoặc `oob` chỉ được mô phỏng trong container có timeout/CPU/memory cap và không có outbound network."""

    payload_intro = """Các block dưới đây được giữ để technical review. `static-verified` chỉ xác nhận cấu trúc/annotation đã qua gate tĩnh; nó **không** chứng minh payload hoạt động trên mọi phiên bản. Trước khi chạy phải đối chiếu `context`, điều kiện cần, encoding, expected result và risk. Payload mở rộng thuộc `cheatsheets/`; lesson chỉ giữ ví dụ cốt lõi."""

    detection = """- Ghi log actor/session, route hoặc operation, object/resource, kết quả policy và correlation ID; không ghi secret hoặc toàn bộ token.
- So sánh authorization/validation failure với baseline hợp lệ và cảnh báo theo chuỗi hành vi, không chỉ theo một chuỗi payload.
- Kết hợp telemetry ứng dụng, reverse proxy và datastore để xác nhận request đã tới sink và có/không có tác động.
- Scanner hoặc WAF alert chỉ là tín hiệu điều tra; không phải bằng chứng duy nhất rằng lỗ hổng tồn tại. [S1]"""

    defense = f"""### Kiểm soát bắt buộc

- {PRIMARY_CONTROL[group]}
- Đặt kiểm soát ở trust boundary có thẩm quyền và kiểm tra thất bại theo fail-closed khi phù hợp.
- Dùng cùng một policy cho mọi route/operation tương đương; không chỉ sửa endpoint xuất hiện trong PoC.

### Defense-in-depth

Các biện pháp dưới đây hỗ trợ giảm blast radius hoặc tăng khả năng phát hiện. Rate limit, UUID khó đoán, WAF, CSP hoặc validation chung không được dùng để thay thế kiểm soát gốc.

{sections['Biện pháp phòng thủ']}"""

    retest = """- **Positive case:** luồng hợp lệ vẫn hoạt động đúng cho actor và dữ liệu được phép.
- **Negative case:** cùng input/tài nguyên nhưng actor hoặc context không được phép bị từ chối mà không rò rỉ chi tiết nhạy cảm.
- **Boundary case:** kiểm tra giá trị rỗng, cực biên, encoding khác, request lặp, trạng thái phiên hết hạn và đường dẫn/operation tương đương.
- **Telemetry:** xác nhận policy decision, application log, proxy log và datastore side effect khớp correlation ID.
- **Regression:** lưu testcase tối thiểu tái hiện lỗi cũ và testcase chứng minh bản sửa không phụ thuộc WAF/rate limit."""

    mistakes = """- Chỉ kiểm tra status code hoặc chuỗi phản hồi mà không xác nhận side effect và log.
- Dùng payload đúng cú pháp nhưng sai DBMS, browser, framework, protocol hoặc injection context.
- Coi UUID, rate limit, WAF, CSP hoặc input validation chung là bản sửa cho một kiểm soát gốc khác.
- Chỉ sửa một route trong khi cùng sink/policy được dùng ở route khác.
- Đánh dấu `verified` dù nguồn, phiên bản fixture hoặc evidence payload chưa được lưu."""

    checklist = """- [ ] Root cause, hậu quả và kỹ thuật khai thác đã được tách riêng.
- [ ] Actor, role/authentication, trust boundary, công nghệ và phiên bản đã rõ.
- [ ] Payload có ID duy nhất, context, encoding, điều kiện, expected result, risk, validation và source.
- [ ] Code dễ lỗi/an toàn dùng cùng framework, phiên bản và use case.
- [ ] Kiểm soát bắt buộc không bị thay thế bằng defense-in-depth.
- [ ] Positive, negative, boundary case và telemetry đã qua retest.
- [ ] Claim nhạy cảm có source marker và mọi link chỉ nằm ở mục 16–17.
- [ ] Cleanup hoàn tất; không còn secret, target thật, callback Internet hoặc dữ liệu khách hàng."""

    parts = [
        frontmatter(path, title, cwes, payload_count > 0),
        f"# {title}",
        warning,
        "## 1. Mục tiêu học tập\n\n" + goal,
        "## 2. Kiến thức cần có\n\n" + prerequisite,
        "## 3. Kiến thức nền tảng\n\n" + sections["Kiến thức Nền tảng"],
        "## 4. Mô tả và nguyên nhân gốc\n\n" + root_cause,
        "## 5. Mô hình đe dọa và điều kiện khai thác\n\n" + threat_model,
        "## 6. Cơ chế tấn công\n\n" + mechanism,
        "## 7. Kiểm thử trong lab được ủy quyền\n\n" + lab,
        "## 8. Payload và phạm vi áp dụng\n\n" + payload_intro + "\n\n" + payloads,
        "## 9. Code dễ bị lỗi và code an toàn\n\n" + sections["Code Example"],
        "## 10. Phát hiện\n\n" + detection,
        "## 11. Phòng thủ\n\n" + defense,
        "## 12. Retest\n\n" + retest,
        "## 13. Sai lầm thường gặp\n\n" + mistakes,
        "## 14. Tóm tắt và checklist\n\n" + checklist,
        "## 15. Giải thích thuật ngữ\n\n" + sections["Giải thích thuật ngữ"],
        "## 16. Bài liên quan và đọc thêm\n\n" + sections["Xem thêm"],
        "## 17. Tài liệu tham khảo\n\n" + reference_section(sources),
    ]
    return "\n\n".join(parts).rstrip() + "\n"


def write_baseline(paths: list[Path]) -> None:
    destination = ROOT / "audit" / "baseline-manifest.tsv"
    destination.parent.mkdir(parents=True, exist_ok=True)
    rows = ["sha256\tbytes\tpath"]
    originals = [*paths, ROOT / "security_cheatsheet.md"]
    for path in originals:
        data = path.read_bytes()
        rows.append(f"{hashlib.sha256(data).hexdigest()}\t{len(data)}\t{path.relative_to(ROOT)}")
    destination.write_text("\n".join(rows) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true", help="write migrated lessons")
    parser.add_argument("--baseline", action="store_true", help="write the original 78-file manifest")
    args = parser.parse_args()

    paths = lesson_paths()
    if len(paths) != 77:
        raise SystemExit(f"expected 77 lessons, found {len(paths)}")
    if args.baseline:
        write_baseline(paths)

    migrated = [(path, migrate(path)) for path in paths]
    if args.write:
        for path, content in migrated:
            path.write_text(content, encoding="utf-8", newline="\n")
    print(f"lessons={len(migrated)} write={args.write} baseline={args.baseline}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
