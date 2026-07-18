#!/usr/bin/env python3
"""Syntax-check only payload/code blocks explicitly marked runnable=true."""

from __future__ import annotations

import ast
import json
import re
import subprocess
import tempfile
import textwrap
from pathlib import Path

import yaml

from validate_content import ROOT, code_fences, parse_annotations


def check(language: str, body: str) -> str | None:
    try:
        if language == "python":
            ast.parse(body)
        elif language == "json":
            json.loads(body)
        elif language in {"yaml", "yml"}:
            yaml.safe_load(body)
        elif language == "javascript":
            with tempfile.NamedTemporaryFile("w", suffix=".js", encoding="utf-8") as handle:
                handle.write(body)
                handle.flush()
                process = subprocess.run(["node", "--check", handle.name], capture_output=True, text=True, timeout=10)
                if process.returncode:
                    return process.stderr.strip()
        elif language == "bash":
            process = subprocess.run(["bash", "-n"], input=body, capture_output=True, text=True, timeout=10)
            if process.returncode:
                return process.stderr.strip()
        elif language == "http":
            first = next((line for line in body.splitlines() if line.strip()), "")
            if not re.fullmatch(r"[A-Z]+\s+\S+\s+HTTP/(?:1\.0|1\.1|2)", first):
                return "invalid HTTP request line"
        return None
    except Exception as exc:  # noqa: BLE001 - report fixture/parser errors uniformly
        return str(exc)


def main() -> int:
    errors = []
    checked = 0
    paths = sorted(ROOT.rglob("*.md"))
    for path in paths:
        if ".git" in path.parts:
            continue
        text = path.read_text(encoding="utf-8")
        lines = text.splitlines()
        for start, language, body_lines in code_fences(text):
            fields = parse_annotations(lines, start)
            if fields.get("runnable") != "true":
                continue
            checked += 1
            failure = check(language, textwrap.dedent("\n".join(body_lines)))
            if failure:
                errors.append(f"{path.relative_to(ROOT)}:{start + 1}: {failure}")
    print(f"runnable_blocks={checked} failures={len(errors)}")
    for error in errors:
        print(f"ERROR {error}")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
