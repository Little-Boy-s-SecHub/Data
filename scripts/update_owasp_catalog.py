#!/usr/bin/env python3
"""Pin OWASP Top 10:2025 CWE mappings and optionally apply them to lessons."""

from __future__ import annotations

import argparse
import json
import re
import urllib.request
from pathlib import Path

import yaml

from validate_content import ROOT, split_frontmatter


API = "https://api.github.com/repos/OWASP/Top10"
TOPIC_OVERRIDES = {
    "business-logic-vulnerabilities": ["A06:2025"],
    "lax-security-settings": ["A02:2025"],
    "session-hijacking": ["A07:2025"],
    "subdomain-squatting": ["A03:2025"],
}


def get_json(url: str):
    request = urllib.request.Request(url, headers={"User-Agent": "SecHub-Data-catalog/1.0"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def get_text(url: str) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": "SecHub-Data-catalog/1.0"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read().decode("utf-8")


def build_catalog() -> dict:
    branch = get_json(f"{API}/branches/master")
    commit = branch["commit"]["sha"]
    directory = get_json(f"{API}/contents/2025/docs/en?ref={commit}")
    categories: dict[str, dict] = {}
    cwe_to_categories: dict[str, list[str]] = {}
    for item in directory:
        match = re.fullmatch(r"(A\d{2})_2025-(.+)\.md", item["name"])
        if not match:
            continue
        category = f"{match.group(1)}:2025"
        raw_url = f"https://raw.githubusercontent.com/OWASP/Top10/{commit}/{item['path']}"
        text = get_text(raw_url)
        mapped = re.split(r"(?m)^#{2,3} List of Mapped CWEs\s*$", text, maxsplit=1)
        if len(mapped) != 2:
            raise ValueError(f"mapped CWE section missing in {item['name']}")
        cwes = sorted(set(re.findall(r"CWE-\d+", mapped[1])), key=lambda value: int(value.split("-")[1]))
        categories[category] = {
            "title": match.group(2).replace("_", " "),
            "source": raw_url,
            "cwes": cwes,
        }
        for cwe in cwes:
            cwe_to_categories.setdefault(cwe, []).append(category)
    if len(categories) != 10:
        raise ValueError(f"expected 10 OWASP categories, found {len(categories)}")
    return {
        "source_repository": "https://github.com/OWASP/Top10",
        "source_commit": commit,
        "edition": 2025,
        "categories": categories,
        "cwe_to_categories": cwe_to_categories,
        "topic_overrides": TOPIC_OVERRIDES,
    }


def apply_catalog(catalog: dict) -> int:
    changed = 0
    for path in sorted(ROOT.glob("[0-9][0-9]-*/**/README.md")):
        text = path.read_text(encoding="utf-8")
        metadata, _ = split_frontmatter(text)
        slug = metadata["slug"]
        if path.relative_to(ROOT).parts[0].startswith("11-"):
            continue
        categories = TOPIC_OVERRIDES.get(slug)
        if categories is None:
            categories = sorted(
                {
                    category
                    for cwe in metadata["cwe"]
                    for category in catalog["cwe_to_categories"].get(cwe, [])
                }
            )
        replacement = (
            "owasp:\n" + "\n".join(f"  - {item}" for item in categories) + "\ncwe:"
            if categories
            else "owasp: []\ncwe:"
        )
        updated, count = re.subn(
            r"(?m)^owasp:(?: \[\])?\n(?:(?:  - .+)\n)*cwe:",
            replacement,
            text,
            count=1,
        )
        if count != 1:
            raise ValueError(f"unable to replace OWASP metadata in {path}")
        if updated != text:
            path.write_text(updated, encoding="utf-8", newline="\n")
            changed += 1
    return changed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    catalog = build_catalog()
    destination = ROOT / "data" / "owasp-top10-2025-cwe-map.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(catalog, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    changed = apply_catalog(catalog) if args.apply else 0
    print(f"source_commit={catalog['source_commit']} categories=10 changed_lessons={changed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
