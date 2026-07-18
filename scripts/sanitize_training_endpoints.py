#!/usr/bin/env python3
"""Replace live-looking placeholder domains with RFC-reserved lab names."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPLACEMENTS = (
    ("your-xss-hunter.xss.ht", "callback.lab.test"),
    ("your-interactsh-domain.com", "callback.lab.test"),
    ("your-oob-domain.com", "callback.lab.test"),
    ("127.0.0.1.nip.io", "loopback.lab.test"),
    ("trusted.com.nip.io", "trusted-bypass.lab.test"),
    ("api.target.com", "api.victim.lab.test"),
    ("target.com", "victim.lab.test"),
    ("vulnerable.com", "victim.lab.test"),
    ("vulnerable-app.com", "victim.lab.test"),
    ("your-bank.com", "bank.lab.test"),
    ("victim.com", "victim.lab.test"),
    ("bank.com", "bank.lab.test"),
    ("evil-phishing.com", "callback.lab.test"),
    ("evil-bank.com", "callback.lab.test"),
    ("evil-site.com", "callback.lab.test"),
    ("attacker.com", "callback.lab.test"),
    ("evil.com", "callback.lab.test"),
    ("auth.provider.com", "auth.provider.lab.test"),
    ("oauth.provider.com", "oauth.provider.lab.test"),
    ("trusted.com", "trusted.lab.test"),
    ("insecure-domain.com", "insecure.lab.test"),
    ("targetxcom.com", "victim-lookalike.lab.test"),
    ("docs.company.com", "docs.company.lab.test"),
    ("api.legit.com", "api.legit.lab.test"),
    ("example.com", "victim.lab.test"),
)


def main() -> int:
    changed = 0
    replacements = 0
    for path in sorted(ROOT.rglob("*.md")):
        if any(part in {".git", "audit", "node_modules", "test-results", "playwright-report"} for part in path.parts):
            continue
        text = path.read_text(encoding="utf-8")
        updated = text
        for old, new in REPLACEMENTS:
            replacements += updated.count(old)
            updated = updated.replace(old, new)
        if updated != text:
            path.write_text(updated, encoding="utf-8", newline="\n")
            changed += 1
    print(f"changed_files={changed} replacements={replacements}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
