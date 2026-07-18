#!/usr/bin/env python3
"""Ensure fenced examples do not contact public Internet targets by default."""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from urllib.parse import urlparse

from validate_content import ROOT, code_fences


URL_RE = re.compile(r"https?://[^\s\"'<>]+")
IDENTIFIER_HOSTS = {"www.w3.org", "apache.org", "xml.org"}


def content_paths() -> list[Path]:
    return sorted(
        [
            *ROOT.glob("[0-9][0-9]-*/**/README.md"),
            *(ROOT / "cheatsheets").glob("*.md"),
        ]
    )


def safe_host(host: str, line: str) -> bool:
    host = host.lower().rstrip(".")
    if host in IDENTIFIER_HOSTS:
        return True
    host = host.split("$", 1)[0]
    if host == "localhost" or host.endswith((".test", ".localhost")) or "." not in host:
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        # Canonical alternate loopback representations retained for SSRF labs.
        return host in {"2130706433", "0x7f000001", "0177.0000.0000.0001", "127.1"}
    return not address.is_global


def main() -> int:
    errors: list[str] = []
    checked = 0
    for path in content_paths():
        text = path.read_text(encoding="utf-8")
        for start, _language, body in code_fences(text):
            for offset, line in enumerate(body, start=1):
                for match in URL_RE.finditer(line):
                    checked += 1
                    url = match.group(0).rstrip("),;")
                    try:
                        host = urlparse(url).hostname or ""
                    except ValueError:
                        errors.append(
                            f"{path.relative_to(ROOT)}:{start + offset + 1}: malformed URL in fenced example: {url}"
                        )
                        continue
                    if not safe_host(host, line):
                        errors.append(
                            f"{path.relative_to(ROOT)}:{start + offset + 1}: public host in fenced example: {host}"
                        )
    for error in errors:
        print(f"ERROR {error}")
    print(f"Training endpoint scan: URLs={checked}; errors={len(errors)}")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
