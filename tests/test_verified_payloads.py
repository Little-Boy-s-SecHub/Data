from __future__ import annotations

import base64
import json
import re
import textwrap
import unittest
import xml.etree.ElementTree as ElementTree
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HTTP_SMUGGLING = ROOT / "08-data-integrity-failures" / "http-request-smuggling" / "README.md"
JWT_ATTACKS = ROOT / "07-authentication-failures" / "jwt-attacks" / "README.md"
XML_BOMBS = ROOT / "10-exceptional-conditions" / "xml-bombs" / "README.md"


def payload_code(path: Path, payload_id: str, language: str) -> str:
    text = path.read_text(encoding="utf-8")
    pattern = re.compile(
        rf"<!-- payload-id: {re.escape(payload_id)} -->.*?"
        rf"```{re.escape(language)}\n(.*?)\n\s*```",
        re.DOTALL,
    )
    match = pattern.search(text)
    if not match:
        raise AssertionError(f"annotated {language} payload not found: {payload_id}")
    return textwrap.dedent(match.group(1))


def framing_policy(raw: bytes) -> str:
    head, separator, body = raw.partition(b"\r\n\r\n")
    if not separator:
        return "REJECT_INVALID_FRAMING"
    headers: dict[bytes, list[bytes]] = {}
    for line in head.split(b"\r\n")[1:]:
        if b":" not in line:
            return "REJECT_INVALID_FRAMING"
        name, value = line.split(b":", 1)
        headers.setdefault(name.strip().lower(), []).append(value.strip().lower())
    if b"content-length" in headers and b"transfer-encoding" in headers:
        return "REJECT_AMBIGUOUS_FRAMING"
    if b"content-length" in headers:
        try:
            expected = int(headers[b"content-length"][0])
        except ValueError:
            return "REJECT_INVALID_FRAMING"
        if len(body) != expected:
            return "REJECT_LENGTH_MISMATCH"
    return "ACCEPT"


class VerifiedPayloadTests(unittest.TestCase):
    def test_http_framing_fixture_is_bounded_and_rejected(self) -> None:
        code = payload_code(HTTP_SMUGGLING, "WEB-A08-HTTP-REQUEST-SMUGGLING-001", "python")
        self.assertNotRegex(code, r"(?m)^\s*(?:from|import)\s+socket")
        namespace: dict[str, object] = {}
        exec(compile(code, str(HTTP_SMUGGLING), "exec"), {"__builtins__": {"len": len}}, namespace)
        raw = namespace["AMBIGUOUS_REQUEST"]
        self.assertIsInstance(raw, bytes)
        self.assertEqual(len(namespace["BODY"]), 6)
        self.assertEqual(framing_policy(raw), "REJECT_AMBIGUOUS_FRAMING")

    def test_jwt_none_fixture_is_bounded_and_fixed_policy_rejects_it(self) -> None:
        code = payload_code(JWT_ATTACKS, "WEB-A07-JWT-ATTACKS-001", "python")
        namespace: dict[str, object] = {}
        exec(compile(code, str(JWT_ATTACKS), "exec"), namespace)
        token = namespace["forged_token"]
        self.assertIsInstance(token, str)
        self.assertEqual(token.count("."), 2)
        header_segment, payload_segment, signature_segment = token.split(".")
        self.assertEqual(signature_segment, "")

        def decode(segment: str) -> dict[str, object]:
            padding = "=" * (-len(segment) % 4)
            return json.loads(base64.urlsafe_b64decode(segment + padding))

        header = decode(header_segment)
        claims = decode(payload_segment)
        self.assertEqual(header["alg"], "none")
        self.assertEqual(claims["role"], "admin")

        def fixed_verifier(candidate: str) -> bool:
            candidate_header = decode(candidate.split(".", 1)[0])
            return candidate_header.get("alg") == "RS256"

        self.assertFalse(fixed_verifier(token))

    def test_xml_bomb_fixture_is_bounded_and_dtd_policy_rejects_it(self) -> None:
        document = payload_code(XML_BOMBS, "WEB-A10-XML-BOMBS-001", "xml")
        self.assertLess(len(document.encode("utf-8")), 1024)
        parsed = ElementTree.fromstring(document)
        self.assertEqual(parsed.text, "lol" * 100)

        def hardened_parse(xml_text: str):
            if "<!DOCTYPE" in xml_text.upper() or "<!ENTITY" in xml_text.upper():
                raise ValueError("DTD and entity declarations are disabled")
            return ElementTree.fromstring(xml_text)

        with self.assertRaisesRegex(ValueError, "DTD and entity"):
            hardened_parse(document)


if __name__ == "__main__":
    unittest.main()
