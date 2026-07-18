#!/usr/bin/env python3
"""Scheduled external-link checker with retry and a small on-disk cache."""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import ipaddress
import json
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

from validate_content import markdown_lines_outside_fences, split_frontmatter


ROOT = Path(__file__).resolve().parents[1]
# A semicolon separates multiple provenance URLs in TSV fields; it is not part
# of either URL. Excluding it prevents two valid links from becoming one 404.
URL_RE = re.compile(r"https?://[^\s<>\"'`;]+")
USER_AGENT = "SecHub-Data-link-check/1.0 (+authorized curriculum QA)"


def urls() -> list[str]:
    found: set[str] = set()

    def collect(text: str) -> None:
        for match in URL_RE.finditer(text):
            url = match.group(0).rstrip(".,;:")
            while url.endswith(")") and url.count(")") > url.count("("):
                url = url[:-1]
            hostname = (urlparse(url).hostname or "").lower()
            if hostname.endswith((".invalid", ".test", ".localhost", ".local", ".internal")) or hostname == "localhost":
                continue
            try:
                address = ipaddress.ip_address(hostname)
            except ValueError:
                pass
            else:
                if not address.is_global:
                    continue
            found.add(url)

    for path in ROOT.rglob("*.md"):
        if any(part in {".git", "node_modules", "test-results", "playwright-report"} for part in path.parts):
            continue
        text = path.read_text(encoding="utf-8")
        if path.name == "README.md" and path != ROOT / "README.md":
            try:
                _metadata, body = split_frontmatter(text)
                text = body.split("## 17. Tài liệu tham khảo", 1)[-1]
            except ValueError:
                pass
        elif path.parent == ROOT / "cheatsheets" and "## Tài liệu tham khảo" in text:
            text = text.rsplit("## Tài liệu tham khảo", 1)[-1]
        text = "\n".join(line for _, line in markdown_lines_outside_fences(text))
        collect(text)
    for path in sorted((ROOT / "data").glob("*.json")):
        collect(path.read_text(encoding="utf-8"))
    obsidian_index = ROOT / "audit" / "obsidian-source-index.tsv"
    if obsidian_index.exists():
        collect(obsidian_index.read_text(encoding="utf-8"))
    return sorted(found)


def check(url: str, retries: int) -> dict:
    last_error = ""
    for attempt in range(retries + 1):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(request, timeout=25) as response:
                status = getattr(response, "status", 200)
                return {"url": url, "status": status, "final_url": response.geturl(), "ok": status < 400}
        except urllib.error.HTTPError as exc:
            if exc.code in {401, 403, 405, 429}:
                return {
                    "url": url,
                    "status": exc.code,
                    "final_url": exc.geturl(),
                    "ok": True,
                    "note": "access-restricted-or-rate-limited",
                }
            if exc.code not in {408, 425, 429, 500, 502, 503, 504}:
                return {"url": url, "status": exc.code, "final_url": exc.geturl(), "ok": False}
            last_error = f"HTTP {exc.code}"
        except Exception as exc:  # noqa: BLE001 - all network failures enter the retry ledger
            last_error = type(exc).__name__ + ": " + str(exc)
        if attempt < retries:
            time.sleep(min(2**attempt, 4))
    return {"url": url, "status": None, "final_url": None, "ok": False, "error": last_error}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--retries", type=int, default=2)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--cache-hours", type=int, default=24)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    now = dt.datetime.now(dt.timezone.utc)
    cached: dict[str, dict] = {}
    if args.output.exists():
        previous = json.loads(args.output.read_text(encoding="utf-8"))
        checked = dt.datetime.fromisoformat(previous["checked_at"])
        if now - checked < dt.timedelta(hours=args.cache_hours):
            cached = {item["url"]: item for item in previous.get("results", [])}

    targets = urls()
    results = [cached[url] for url in targets if url in cached]
    missing = [url for url in targets if url not in cached]
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        results.extend(executor.map(lambda value: check(value, args.retries), missing))
    results.sort(key=lambda item: item["url"])
    payload = {"checked_at": now.isoformat(), "count": len(results), "results": results}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    broken = [item for item in results if not item["ok"]]
    print(f"links={len(results)} cached={len(results) - len(missing)} broken={len(broken)}")
    for item in broken:
        print(f"BROKEN {item.get('status')} {item['url']} {item.get('error', '')}")
    return 1 if broken else 0


if __name__ == "__main__":
    raise SystemExit(main())
