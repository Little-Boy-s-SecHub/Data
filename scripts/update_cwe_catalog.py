#!/usr/bin/env python3
"""Pin official MITRE CWE IDs/names for offline CI validation."""

from __future__ import annotations

import argparse
import io
import json
import urllib.request
import zipfile
from pathlib import Path
from xml.etree import ElementTree


ROOT = Path(__file__).resolve().parents[1]
URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, help="use an already downloaded official ZIP")
    args = parser.parse_args()

    data = args.input.read_bytes() if args.input else urllib.request.urlopen(URL, timeout=60).read()
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        names = archive.namelist()
        if len(names) != 1:
            raise SystemExit(f"unexpected CWE archive entries: {names}")
        root = ElementTree.fromstring(archive.read(names[0]))

    weaknesses: dict[str, dict[str, str | None]] = {}
    for element in root.iter():
        if element.tag.endswith("Weakness") and "ID" in element.attrib:
            weaknesses[f"CWE-{element.attrib['ID']}"] = {
                "name": element.attrib["Name"],
                "status": element.attrib.get("Status"),
                "abstraction": element.attrib.get("Abstraction"),
                "structure": element.attrib.get("Structure"),
            }
    if len(weaknesses) < 900:
        raise SystemExit(f"official catalog unexpectedly small: {len(weaknesses)}")

    payload = {
        "source": URL,
        "catalog_version": root.attrib.get("Version"),
        "catalog_date": root.attrib.get("Date"),
        "generated_from_official_xml": True,
        "weaknesses": dict(sorted(weaknesses.items(), key=lambda item: int(item[0].split("-")[1]))),
    }
    destination = ROOT / "data" / "cwe-catalog.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"catalog_version={payload['catalog_version']} weaknesses={len(weaknesses)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
