#!/usr/bin/env python3
"""Verify the immutable 78-file baseline manifest against the pinned commit."""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
COMMIT = "5d3dc8c632eda8df4ab431eb7ce19dc64209cc0c"
MANIFEST = ROOT / "audit" / "baseline-manifest.tsv"


def git_bytes(spec: str) -> bytes:
    return subprocess.run(
        ["git", "show", spec],
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout


def main() -> int:
    rows = MANIFEST.read_text(encoding="utf-8").splitlines()
    errors: list[str] = []
    if not rows or rows[0] != "sha256\tbytes\tpath":
        errors.append("manifest header is invalid")
    records = rows[1:]
    if len(records) != 78:
        errors.append(f"expected 78 baseline records, found {len(records)}")

    paths: set[str] = set()
    for number, row in enumerate(records, start=2):
        try:
            expected_hash, expected_size, path = row.split("\t")
            expected_bytes = int(expected_size)
        except ValueError:
            errors.append(f"line {number}: invalid TSV record")
            continue
        if path in paths:
            errors.append(f"line {number}: duplicate path {path}")
            continue
        paths.add(path)
        try:
            content = git_bytes(f"{COMMIT}:{path}")
        except subprocess.CalledProcessError:
            errors.append(f"line {number}: path absent from pinned commit: {path}")
            continue
        actual_hash = hashlib.sha256(content).hexdigest()
        if actual_hash != expected_hash or len(content) != expected_bytes:
            errors.append(
                f"line {number}: baseline mismatch for {path}: "
                f"sha256={actual_hash}, bytes={len(content)}"
            )

    expected_paths = {
        item.decode()
        for item in subprocess.run(
            ["git", "ls-tree", "-r", "--name-only", "-z", COMMIT],
            cwd=ROOT,
            check=True,
            capture_output=True,
        ).stdout.split(b"\0")
        if item and (item == b"security_cheatsheet.md" or item.endswith(b"/README.md"))
    }
    if paths != expected_paths:
        errors.append(
            f"manifest path set differs from pinned lessons/cheatsheet: "
            f"missing={sorted(expected_paths - paths)}, extra={sorted(paths - expected_paths)}"
        )

    for error in errors:
        print(f"ERROR {error}")
    print(f"Baseline manifest: records={len(records)}; errors={len(errors)}")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
