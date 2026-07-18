#!/usr/bin/env python3
"""Build provenance and payload ledgers from the working tree."""

from __future__ import annotations

import collections
import json
import re
from pathlib import Path
from urllib.parse import urlparse

import yaml

from validate_content import (
    GENERIC_ANNOTATION_MARKERS,
    MECHANICAL_LESSON_MARKERS,
    ROOT,
    code_fences,
    parse_annotations,
    split_frontmatter,
)


UPSTREAM_COMMIT = "5d3dc8c632eda8df4ab431eb7ce19dc64209cc0c"
TODAY = "2026-07-18"
# References may list multiple URLs separated by semicolons. Keep that
# delimiter outside each URL so the source ledger matches the link checker.
URL_RE = re.compile(r"https?://[^\s<>\"'`;]+")
SOURCE_LINE_RE = re.compile(r"^- \*\*\[(S\d+)\]\*\*\s+(.+)$")


def content_files() -> list[Path]:
    lessons = list(ROOT.glob("[0-9][0-9]-*/**/README.md"))
    return sorted(lessons) + sorted((ROOT / "cheatsheets").glob("*.md"))


def clean_url(raw: str) -> str:
    url = raw.rstrip(".,;:—")
    while url.endswith(")") and url.count(")") > url.count("("):
        url = url[:-1]
    return url


def source_tier(url: str) -> str:
    host = (urlparse(url).hostname or "").lower()
    if host.endswith(
        (
            "rfc-editor.org",
            "ietf.org",
            "w3.org",
            "whatwg.org",
            "nist.gov",
            "mitre.org",
            "python.org",
            "nodejs.org",
            "mozilla.org",
            "microsoft.com",
            "oracle.com",
            "postgresql.org",
            "mysql.com",
            "php.net",
            "flask.palletsprojects.com",
            "expressjs.com",
            "apache.org",
            "readthedocs.io",
            "slsa.dev",
            "v8.dev",
            "withgoogle.com",
            "docs.npmjs.com",
            "nginx.org",
            "hstspreload.org",
            "palletsprojects.com",
        )
    ):
        return "tier-1-standard-or-official"
    if host.endswith("owasp.org"):
        return "tier-2-authoritative-guidance"
    if host.endswith("portswigger.net"):
        return "tier-3-practical-research"
    if host.endswith(("snyk.io", "contextis.com", "auth0.com", "docs.pwntools.com")) or host == "omergil.blogspot.com":
        return "tier-3-practical-research"
    if host in {
        "github.com",
        "book.hacktricks.xyz",
        "book.hacktricks.wiki",
        "swisskyrepo.github.io",
        "www.christian-schneider.net",
    }:
        return "tier-4-community"
    return "unclassified-review-required"


def extract_sources(path: Path) -> list[dict]:
    records: list[dict] = []
    text = path.read_text(encoding="utf-8")
    for line_number, line in enumerate(text.splitlines(), start=1):
        match = SOURCE_LINE_RE.match(line)
        if not match:
            continue
        source_id = match.group(1)
        title = match.group(2).split("http", 1)[0].strip(" .—")
        for url_match in URL_RE.finditer(line):
            url = clean_url(url_match.group(0))
            records.append(
                {
                    "path": str(path.relative_to(ROOT)),
                    "line": line_number,
                    "source_id": source_id,
                    "title": title,
                    "url": url,
                    "tier": source_tier(url),
                    "accessed": TODAY,
                    "usage": "reference-link-and-paraphrase",
                    "license_review": "reference-link; baseline rights tracked separately",
                }
            )
    return records


def build_provenance() -> None:
    decision = yaml.safe_load((ROOT / "audit" / "provenance-decision.yml").read_text(encoding="utf-8"))
    rights_status = decision.get("baseline_rights", {}).get("status", "pending-owner-decision")
    rights_note = (
        "Quyền baseline đã được ghi nhận trong audit/provenance-decision.yml."
        if rights_status == "resolved"
        else "Trạng thái giấy phép upstream chưa được chủ sở hữu xác nhận. Ma trận này ghi nguồn, không tự cấp quyền tái sử dụng."
    )
    rows = [
        "# Content provenance matrix",
        "",
        f"Cập nhật: {TODAY}. Baseline upstream: `{UPSTREAM_COMMIT}`.",
        "",
        f"> {rights_note}",
        "",
        "| Tệp | Nguồn baseline | Nguồn ngoài được liệt kê | Quyền sử dụng | Technical review |",
        "|---|---|---:|---|---|",
    ]
    for path in content_files():
        source_count = len({record["url"] for record in extract_sources(path)})
        relative = path.relative_to(ROOT)
        baseline = f"upstream@{UPSTREAM_COMMIT}" if path.name == "README.md" else "legacy security_cheatsheet.md"
        technical_review = "pending"
        if path.name == "README.md":
            metadata, _body = split_frontmatter(path.read_text(encoding="utf-8"))
            technical_review = "complete" if metadata.get("content_status") == "verified" else "pending"
        rows.append(f"| `{relative}` | {baseline} | {source_count} | {rights_status} | {technical_review} |")
    (ROOT / "CONTENT_PROVENANCE.md").write_text("\n".join(rows) + "\n", encoding="utf-8")


def build_source_ledger() -> list[dict]:
    records = [record for path in content_files() for record in extract_sources(path)]
    unique_urls = sorted({record["url"] for record in records})
    payload = {
        "schema_version": 1,
        "generated": TODAY,
        "usage_note": "Nguồn ngoài được dùng làm liên kết và cơ sở paraphrase; quyền của nội dung baseline vẫn chờ chủ sở hữu quyết định.",
        "occurrence_count": len(records),
        "unique_url_count": len(unique_urls),
        "sources": records,
    }
    destination = ROOT / "audit" / "source-ledger.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return records


def build_payload_ledger() -> list[dict]:
    records = []
    for path in content_files():
        text = path.read_text(encoding="utf-8")
        metadata = {}
        if path.name == "README.md":
            try:
                metadata, text = split_frontmatter(text)
            except (ValueError, yaml.YAMLError):
                pass
        lines = text.splitlines()
        for start, language, body in code_fences(text):
            annotation = parse_annotations(lines, start)
            if not annotation:
                continue
            records.append(
                {
                    "payload_id": annotation.get("payload-id"),
                    "path": str(path.relative_to(ROOT)),
                    "line": start + 1,
                    "language": language or "text",
                    "risk": annotation.get("risk"),
                    "runnable": annotation.get("runnable") == "true",
                    "validation": annotation.get("validation"),
                    "evidence": annotation.get("evidence"),
                    "lesson_status": metadata.get("content_status"),
                    "body_sha256": __import__("hashlib").sha256("\n".join(body).encode()).hexdigest(),
                    "mechanical_placeholder": any(
                        marker in annotation.get(field, "")
                        for field in ("context", "prerequisites", "encoding", "expected-result")
                        for marker in GENERIC_ANNOTATION_MARKERS
                    ),
                }
            )
    payload_blockers = []
    placeholder_count = sum(item["mechanical_placeholder"] for item in records)
    if placeholder_count:
        payload_blockers.append(f"{placeholder_count} payloads still contain mechanical annotation placeholders")
    missing_lab_evidence = sum(
        item.get("validation") == "lab-verified" and not item.get("evidence") for item in records
    )
    if missing_lab_evidence:
        payload_blockers.append(f"{missing_lab_evidence} lab-verified payloads lack regression evidence")
    ledger = {
        "schema_version": 1,
        "generated": TODAY,
        "payload_release_ready": not payload_blockers,
        "blockers": payload_blockers,
        "count": len(records),
        "payloads": records,
    }
    destination = ROOT / "audit" / "payload-ledger.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(ledger, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return records


def build_cwe_mapping_ledger() -> None:
    catalog = json.loads((ROOT / "data" / "cwe-catalog.json").read_text(encoding="utf-8"))
    weaknesses = catalog["weaknesses"]
    lessons = []
    for path in sorted(ROOT.glob("[0-9][0-9]-*/**/README.md")):
        metadata, _body = split_frontmatter(path.read_text(encoding="utf-8"))
        mappings = []
        for cwe in metadata.get("cwe", []):
            entry = weaknesses.get(cwe, {})
            mappings.append(
                {
                    "id": cwe,
                    "name": entry.get("name"),
                    "status": entry.get("status"),
                    "abstraction": entry.get("abstraction"),
                    "structure": entry.get("structure"),
                }
            )
        lessons.append(
            {
                "lesson_id": metadata.get("id"),
                "path": str(path.relative_to(ROOT)),
                "mappings": mappings,
                "root_cause_fit": "human-review-required",
            }
        )
    payload = {
        "schema_version": 1,
        "catalog_version": catalog.get("catalog_version"),
        "catalog_date": catalog.get("catalog_date"),
        "lessons": lessons,
    }
    (ROOT / "audit" / "cwe-mapping-ledger.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def build_release_readiness(payloads: list[dict], sources: list[dict]) -> None:
    statuses: collections.Counter[str] = collections.Counter()
    mechanical_lessons = 0
    for path in sorted(ROOT.glob("[0-9][0-9]-*/**/README.md")):
        metadata, body = split_frontmatter(path.read_text(encoding="utf-8"))
        statuses[str(metadata.get("content_status"))] += 1
        if any(marker in body for marker in MECHANICAL_LESSON_MARKERS):
            mechanical_lessons += 1

    generic_payloads = 0
    for path in content_files():
        text = path.read_text(encoding="utf-8")
        lines = text.splitlines()
        for start, _language, _body in code_fences(text):
            annotation = parse_annotations(lines, start)
            if annotation and any(
                marker in annotation.get(field, "")
                for field in ("context", "prerequisites", "encoding", "expected-result")
                for marker in GENERIC_ANNOTATION_MARKERS
            ):
                generic_payloads += 1

    validation_counts = collections.Counter(str(item.get("validation")) for item in payloads)
    risk_counts = collections.Counter(str(item.get("risk")) for item in payloads)
    unclassified_sources = sum(item["tier"] == "unclassified-review-required" for item in sources)
    license_blocked = "BLOCKED" in (ROOT / "LICENSE-STATUS.md").read_text(encoding="utf-8")
    external_link_status = "chưa chạy"
    external_path = ROOT / "audit" / "external-link-status.json"
    if external_path.exists():
        external = json.loads(external_path.read_text(encoding="utf-8"))
        broken = sum(not item.get("ok", False) for item in external.get("results", []))
        external_link_status = f"{external.get('count', 0)} link, {broken} lỗi cứng"

    blockers = []
    if statuses.get("verified", 0) != 77:
        blockers.append(f"{77 - statuses.get('verified', 0)} bài chưa đạt content_status: verified")
    if mechanical_lessons:
        blockers.append(f"{mechanical_lessons} bài còn template migration ở threat model/lab/phòng thủ")
    if generic_payloads:
        blockers.append(f"{generic_payloads} payload còn annotation placeholder, chưa có context/encoding/expected result cụ thể")
    if unclassified_sources:
        blockers.append(f"{unclassified_sources} lượt nguồn ngoài chưa được phân loại provenance tự động")
    if license_blocked:
        blockers.append("Quyết định license của nội dung baseline vẫn BLOCKED")
    signoff = yaml.safe_load((ROOT / "audit" / "review-signoff.yml").read_text(encoding="utf-8"))
    reviews_complete = all(
        signoff.get(name, {}).get("status") == "complete"
        and signoff.get(name, {}).get("reviewer")
        and len(signoff.get(name, {}).get("scope", [])) == 77
        and len(signoff.get(name, {}).get("cheatsheets", [])) == 15
        for name in ("technical_review", "language_review")
    )
    if not reviews_complete:
        blockers.append("Technical review và language review độc lập chưa có phê duyệt đầy đủ")

    lines = [
        "# Release readiness",
        "",
        f"Cập nhật: {TODAY}.",
        "",
        "## Trạng thái tự động",
        "",
        f"- Bài học: {sum(statuses.values())}; verified: {statuses.get('verified', 0)}; technical-review: {statuses.get('technical-review', 0)}; draft: {statuses.get('draft', 0)}.",
        f"- Template migration còn lại: {mechanical_lessons} bài; payload annotation placeholder: {generic_payloads}.",
        f"- Payload: {len(payloads)}; static-verified: {validation_counts.get('static-verified', 0)}; lab-verified: {validation_counts.get('lab-verified', 0)}.",
        f"- Risk payload: {', '.join(f'{key}={value}' for key, value in sorted(risk_counts.items()))}.",
        f"- Nguồn: {len(sources)} lượt tham chiếu; {len({item['url'] for item in sources})} URL duy nhất; chưa phân loại: {unclassified_sources}.",
        f"- External link check: {external_link_status}.",
        "",
        "## Blocker public release",
        "",
        *[f"- {item}." for item in blockers],
        "",
        "Kết luận: **chưa sẵn sàng gắn tag v1.0.0 hoặc công bố là học liệu đã kiểm chứng hoàn toàn**.",
    ]
    destination = ROOT / "audit" / "release-readiness.md"
    destination.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    build_provenance()
    sources = build_source_ledger()
    payloads = build_payload_ledger()
    build_cwe_mapping_ledger()
    build_release_readiness(payloads, sources)
    print("built provenance, source/payload/CWE ledgers, and release readiness")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
