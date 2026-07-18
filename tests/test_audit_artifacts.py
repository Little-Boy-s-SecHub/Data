from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from build_audit_artifacts import URL_RE, clean_url  # noqa: E402


class AuditArtifactTests(unittest.TestCase):
    def test_semicolon_separates_reference_urls(self) -> None:
        text = "https://example.test/one;https://example.test/two"
        self.assertEqual(URL_RE.findall(text), ["https://example.test/one", "https://example.test/two"])

    def test_clean_url_removes_markdown_punctuation(self) -> None:
        self.assertEqual(clean_url("https://example.test/reference)."), "https://example.test/reference")


if __name__ == "__main__":
    unittest.main()
