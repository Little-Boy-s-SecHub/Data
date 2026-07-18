from __future__ import annotations

import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"

import sys

sys.path.insert(0, str(SCRIPTS))

from validate_content import evidence_node_exists  # noqa: E402


class EvidenceNodeTests(unittest.TestCase):
    def test_finds_python_test_method(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".py", encoding="utf-8") as handle:
            handle.write("    def test_fixture(self):\n        pass\n")
            handle.flush()
            self.assertTrue(evidence_node_exists(Path(handle.name), "Suite.test_fixture"))

    def test_finds_javascript_async_helper(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".js", encoding="utf-8") as handle:
            handle.write("async function test_browser_fixture(page) {\n  return page;\n}\n")
            handle.flush()
            self.assertTrue(evidence_node_exists(Path(handle.name), "test_browser_fixture"))

    def test_rejects_comment_only_reference(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".js", encoding="utf-8") as handle:
            handle.write("// test_browser_fixture is intentionally absent\n")
            handle.flush()
            self.assertFalse(evidence_node_exists(Path(handle.name), "test_browser_fixture"))


if __name__ == "__main__":
    unittest.main()
