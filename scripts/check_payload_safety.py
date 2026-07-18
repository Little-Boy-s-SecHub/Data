#!/usr/bin/env python3
"""High-confidence static safety checks for annotated payload blocks."""

from __future__ import annotations

import re
from pathlib import Path

from validate_content import ROOT, code_fences, parse_annotations


DESTRUCTIVE = re.compile(
    r"(?:\bDROP\s+(?:TABLE|DATABASE)\b|\bTRUNCATE\s+TABLE\b|\bDELETE\s+FROM\b|"
    r"\brm\s+-rf\b|\bmkfs(?:\.|\s)|\bos\.remove\s*\(|\bshutil\.rmtree\s*\(|\bunlink\s*\()",
    re.IGNORECASE,
)
PUBLIC_OOB = re.compile(
    r"(?:interactsh-client|\.oastify\.com|burpcollaborator\.net|webhook\.site|requestbin\.)",
    re.IGNORECASE,
)
UNBOUNDED_RESOURCE = re.compile(
    r"(?:range\(\s*(?:[1-9]\d{5,})\s*\)|sleep\(\s*(?:[1-9]\d{3,})\s*\)|"
    r"['\"]A['\"]\s*\*\s*(?:100_?000_?000|1_?000_?000_?000))",
    re.IGNORECASE,
)
REAL_SYSTEM_RESOURCE = re.compile(
    r"(?:/etc/(?:passwd|shadow|hostname)|c:\\\\(?:boot\.ini|windows\\)|/proc/self/environ|"
    r"document\.cookie|/bin/(?:sh|bash))",
    re.IGNORECASE,
)
ACTIVE_SHELL_EXEC = re.compile(
    r"(?:system\s*\(\s*\$_(?:GET|POST|REQUEST)|execSync\s*\(|(?:cat|type)\s+/etc/|"
    r"\b(?:bash|sh)\s+-i\b|\bnc\s+[^\n]*\s-e\b)",
    re.IGNORECASE,
)
REQUEST_LINE = re.compile(r"^(?:GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s+\S+\s+HTTP/1\.[01]$")


def content_paths() -> list[Path]:
    return sorted(
        [
            *ROOT.glob("[0-9][0-9]-*/**/README.md"),
            *(ROOT / "cheatsheets").glob("*.md"),
        ]
    )


def simple_content_length_error(body: list[str]) -> str | None:
    """Validate a single, non-smuggling HTTP example when framing is unambiguous."""
    if not body or not REQUEST_LINE.match(body[0].strip()):
        return None
    if any("Transfer-Encoding:" in line for line in body):
        return None
    request_lines = sum(bool(REQUEST_LINE.match(line.strip())) for line in body)
    lengths = [line for line in body if line.lower().startswith("content-length:")]
    if request_lines != 1 or len(lengths) != 1 or "" not in body:
        return None
    try:
        declared = int(lengths[0].split(":", 1)[1].strip())
    except ValueError:
        return "Content-Length is not an integer"
    separator = body.index("")
    actual = len("\r\n".join(body[separator + 1 :]).encode("utf-8"))
    if declared != actual:
        return f"Content-Length declares {declared} bytes but Markdown body has {actual} bytes"
    return None


def main() -> int:
    errors: list[str] = []
    checked = 0
    for path in content_paths():
        text = path.read_text(encoding="utf-8")
        lines = text.splitlines()
        for start, _language, body in code_fences(text):
            annotation = parse_annotations(lines, start)
            if not annotation:
                continue
            checked += 1
            payload_id = annotation.get("payload-id", f"line-{start + 1}")
            payload = "\n".join(body)
            risk = annotation.get("risk", "")
            context = " ".join(
                (annotation.get("context", ""), annotation.get("prerequisites", ""))
            ).lower()

            if DESTRUCTIVE.search(payload):
                if risk != "destructive":
                    errors.append(f"{path.relative_to(ROOT)}:{start + 1}: {payload_id} contains a destructive operation but risk={risk}")
                elif not any(word in context for word in ("disposable", "snapshot", "container")):
                    errors.append(f"{path.relative_to(ROOT)}:{start + 1}: {payload_id} destructive payload lacks disposable-fixture context")
            if PUBLIC_OOB.search(payload):
                errors.append(f"{path.relative_to(ROOT)}:{start + 1}: {payload_id} invokes a public OOB/callback service")
            if "169.254.169.254" in payload and "mock" not in context:
                errors.append(f"{path.relative_to(ROOT)}:{start + 1}: {payload_id} uses a real link-local metadata address instead of an explicit mock")
            if risk == "non-destructive" and UNBOUNDED_RESOURCE.search(payload):
                errors.append(f"{path.relative_to(ROOT)}:{start + 1}: {payload_id} has a high/unbounded resource probe but risk=non-destructive")
            if REAL_SYSTEM_RESOURCE.search(payload):
                errors.append(f"{path.relative_to(ROOT)}:{start + 1}: {payload_id} references a real system/user resource instead of a synthetic fixture")
            if ACTIVE_SHELL_EXEC.search(payload):
                errors.append(f"{path.relative_to(ROOT)}:{start + 1}: {payload_id} contains active shell execution instead of an inert marker")
            if framing := simple_content_length_error(body):
                errors.append(f"{path.relative_to(ROOT)}:{start + 1}: {payload_id} {framing}")

    for error in errors:
        print(f"ERROR {error}")
    print(f"Payload safety: checked={checked}; errors={len(errors)}")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
