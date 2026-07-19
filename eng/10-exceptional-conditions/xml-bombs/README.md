---
schema_version: 1
id: WEB-A10-XML-BOMBS
title: "XML Bombs"
slug: xml-bombs
level: advanced
estimated_minutes: 65
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A02:2025
cwe:
  - CWE-776
  - CWE-400
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# XML Bombs

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain XML Bombs by root cause instead of just describing the consequence.
- Identify trust boundary, asset, actor, and necessary conditions for the flaw to be exploitable.
- Conduct controlled testing in a local lab and distinguish expected results from false positives.
- Choose root control, implement fix, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- Understand the flow of HTTP request/response in the XML Bombs scenario and how to apply input handling across trust boundaries. 
- Distinguish between authentication, authorization, and validation. 
- Be able to read code/configuration in the language or framework appearing in the example. 
- Have an isolated local lab, synthetic data, observable logs, and clear testing permissions.

## 3. Background Knowledge

Imagine you receive a small gift box from the post office. When you open the box, you see inside 10 smaller boxes. Opening each of those smaller boxes, you again see 10 even smaller boxes. This process repeats continuously. At first, the box looks very compact, but when you try to open everything, the huge pile of boxes will overflow the entire room, leaving no space to breathe.
In the XML language, this mechanism is equivalent to **Entity Nesting (XML Entity Nesting)**. XML allows programmers to create "shortcuts" (called entities) through DTD definitions to write code faster. One shortcut can call other nested shortcuts.

When the XML code translation system (XML Parser) reads this file, it will perform the task of translating those shortcuts into actual content (the **Entity Expansion** process). If the parser does not have safety limits, nested structures in exponential form (9 levels, each level referencing the previous entity 10 times) can produce up to a billion substitutions of the original entity. The originally tiny XML file, only a few kilobytes in size, suddenly turns into a 'blockbuster' expanding to hundreds of megabytes or gigabytes of data in RAM. The server cannot keep up, runs out of memory (Out of Memory), and crashes immediately.

### Illustration of normal operation (Normal Operation)```python
# Normal operation: Safe XML parsing with entities disabled using defusedxml
import defusedxml.ElementTree as ET

# Normal XML data representing a simple user profile without recursive entities
normal_xml_data = """<?xml version="1.0" encoding="UTF-8"?>
<profile>
    <name>Jane Doe</name>
    <email>jane.doe@victim.lab.test</email>
    <role>Developer</role>
</profile>
"""

def parse_user_profile(xml_string):
    try:
        # Securely parse the XML string
        # defusedxml automatically blocks dynamic entity expansion and DTD declaration injection
        root = ET.fromstring(xml_string)

        # Extract text content safely from the validated nodes
        name = root.find('name').text
        email = root.find('email').text
        role = root.find('role').text

        print(f"Profile Loaded - Name: {name}, Email: {email}, Role: {role}")
        return {"name": name, "email": email, "role": role}
    except ET.ParseError as e:
        print(f"XML Parsing failed due to syntax or security restriction: {e}")
        return None

# Parse standard, non-malicious XML data
parse_user_profile(normal_xml_data)
```

## 4. Description and Root Cause

The **XML Bomb (commonly encountered through Billion Laughs or Quadratic Blowup)** is a sophisticated trap targeting server memory. It occurs because old XML parsing libraries by default allow users to define internal entities and then excessively expand them.

An attacker only needs to send a very small XML data segment that contains a recursive nested structure. The danger of this vulnerability lies in: 
- The server cannot detect that this file is dangerous just by the upload size (because the file is actually extremely light, easily passing file size filters).
- Only when the parser expands the nested entities does the consumption of CPU/memory increase significantly; the specific result depends on the parser, version, and resource limits. Expat 2.4.1 and above has protection against Billion Laughs, but the Python version linked with the system library may differ, so `pyexpat.EXPAT_VERSION` must be checked. [S4]

> **Reference source:** technical claims in the lesson are tagged with source markers; when applying in practice, compare with the version/framework being used: [S1], [S2], [S3].

## 5. Threat Model and Exploitation Conditions

- **Assets:** CPU, memory, processing time, and workers of XML parser/service.  
- **Trust boundary:** XML body sent by the client into the parser with DTD/general entity configuration and specific expansion limits.  
- **Actor:** local client not logged in or fixture user, only sending XML documents to reduce depth within resource-limited containers.  
- **Necessary conditions:** parser allows entity expansion and lacks/does not have sufficient limits on body, number of entities, depth, or processing time.  
- **Environmental conditions:** Python 3.12; record `pyexpat.EXPAT_VERSION` or actual libxml version; container has no outbound access and has CPU/memory timeout.

Billion Laughs uses internal entities, so blocking outbound does not stop it; to fix it, you must disable DTD/entity when not needed or apply a limit that the parser can check. [S1]

## 6. Attack Mechanism

Nested general entities can cause output to increase faster than input, making the parser consume CPU/memory before the application processes DOM. Testing uses a depth-reduced variant, comparing peak resource/elapsed time with normal XML and confirming safe configuration rejects before expansion. [S1]

## 7. Testing in an Authorized Lab

1. **Setup:** run the parser fixture in a capped container; record Python/parser version, DTD/entity configuration, and baseline resource metrics.
2. **Input:** use valid small XML, XML containing forbidden DTD, and bomb with reduced depth with predefined size/expansion maximum.
3. **Operation:** increase one entity per turn; record elapsed time, peak RSS, exit/status, and parser exception.
4. **Expected result:** error-prone configuration shows clear expansion increase; safe configuration rejects DTD/entity or stops at hard limit while worker remains usable.
5. **Cleanup:** stop fixture, delete temporary XML/log and confirm container has no remaining processes.
6. **Safety limits:** do not run full Billion Laughs; stop before resource cap, do not use external entity or Internet callback.

## 8. Payloads and Scope of Applicability

The blocks below are minimal lab examples according to the context recorded in the annotation. Before use, check the framework/version, encoding, expected result, and risk; only run in an authorized local fixture. Extended payload belongs to `security_cheatsheet.md`; lessons only retain the core examples.

Lesson only keeps limited downgrade seeds to test the policy without causing resource exhaustion. Full payloads like Billion Laughs or Quadratic Blowup are not released in the lesson.

<!-- payload-id: WEB-A10-XML-BOMBS-001 -->
<!-- context: XML 1.0 with an internal DTD; the parser fixture must state the implementation and Expat/libxml version -->
<!-- prerequisites: local container has a timeout, memory/CPU cap, and no outbound network -->
<!-- encoding: UTF-8; complete, uncompressed document -->
<!-- expected-result: the hardened parser rejects DTD/entity expansion; the fixture observes expansion of at most 100 lol strings, then stops without escalation -->
<!-- risk: dos -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S2,S4 -->
<!-- last-verified: 2026-07-17 -->
```xml
<?xml version="1.0"?>
<!DOCTYPE probe [
  <!ENTITY e0 "lol">
  <!ENTITY e1 "&e0;&e0;&e0;&e0;&e0;&e0;&e0;&e0;&e0;&e0;">
  <!ENTITY e2 "&e1;&e1;&e1;&e1;&e1;&e1;&e1;&e1;&e1;&e1;">
]>
<probe>&e2;</probe>
```
**Quadratic Blowup downgrade**

<!-- payload-id: WEB-A10-XML-BOMBS-002 -->
<!-- context: XML 1.0 internal DTD; parser fixture must record implementation and expansion limits -->
<!-- prerequisites: container local has timeout and memory/CPU cap; entity value is intentionally small and repeated count is bounded -->
<!-- encoding: UTF-8; document complete and uncompressed -->
<!-- expected-result: hardened parser rejects DTD/entity expansion; vulnerable fixture records repeated expansion cost without exceeding lab cap -->
<!-- risk: dos -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2,S4 -->
<!-- last-verified: 2026-07-18 -->
```xml
<?xml version="1.0"?>
<!DOCTYPE probe [
  <!ENTITY block "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA">
]>
<probe>&block;&block;&block;&block;&block;&block;&block;&block;</probe>
```

## 9. Vulnerable Code and Secure Code

The two functions below use Python 3.12 and `defusedxml` 0.7.1 for the same use case of parsing small XML documents. The error-prone version turns off all protection flags and does not limit input; the safe version limits bytes before parsing, then disallows DTD, entities, and external references. A timeout/memory cap at the service layer is still needed for defense-in-depth. [S4] [S5]

### Not safe (vulnerable): turn off parser protection

```python
from defusedxml import ElementTree as DefusedET

def parse_xml_vulnerable(xml_text):
    # Vulnerable: all defusedxml protections are explicitly disabled
    return DefusedET.fromstring(
        xml_text,
        forbid_dtd=False,
        forbid_entities=False,
        forbid_external=False,
    )
```
### Secure: limit input and prohibit unnecessary structures

```python
from defusedxml import ElementTree as DefusedET
from defusedxml.common import DefusedXmlException
from xml.etree.ElementTree import ParseError

MAX_XML_BYTES = 64 * 1024

def parse_xml_secure(xml_text):
    raw = xml_text.encode('utf-8')
    if len(raw) > MAX_XML_BYTES:
        raise ValueError('XML document exceeds the configured byte limit')
    try:
        return DefusedET.fromstring(
            xml_text,
            forbid_dtd=True,
            forbid_entities=True,
            forbid_external=True,
        )
    except (DefusedXmlException, ParseError) as exc:
        raise ValueError("Rejected unsafe XML") from exc
```

## 10. Detection

- Log the actor/session, route or operation, object/resource related to XML Bombs, policy results and correlation ID; do not log secrets or full tokens.
- Compare authorization/validation failures with a valid baseline and alert according to behavior chains, not just a single payload chain.
- Combine application telemetry, reverse proxy, and datastore to confirm that the request reached the sink and whether it had any impact.
- Scanner or WAF alert is only an investigation signal; it is not the sole proof that a vulnerability exists. [S1]

## 11. Defense

### Compulsory control

- Limit resources, fail safely, and handle every possible exceptional state.  
- Disable DTD/general entity when not needed; patched parser and set hard limits for body, expansion, depth, CPU/memory, and processing time.  
- Use the same policy for every equivalent route/operation; do not only fix the endpoint that appears in the PoC.

### Defense-in-depth

With XML Bombs, the measures below help reduce the blast radius or increase detection capability. Rate limit, UUID unpredictable, WAF, CSP, or common validation cannot be used to replace the original controls.

- **Summary**: Prevent XML Bomb by completely disabling DTD inline or limiting the maximum number of entity expansions in the XML parser configuration. 
- **Detailed steps**:
  - Completely disable inline DTD (Document Type Definitions) processing in the XML parser.
  - Disable external entity resolution XML (XXE).
  - If DTD is required for business operations, set strict limits on the maximum number of entities allowed to expand, maximum attribute size, and the overall size of the input file.
  - If the business does not require DTD/XML, use a simpler format that can eliminate the entity expansion vector; all formats still need size, depth, and processing time limits.

## 12. Retest

- **Positive case:** with XML Bombs, the valid flow still works correctly for the actor and allowed data.  
- **Negative case:** with the same input/resources but the actor or context is not allowed, it is denied without leaking sensitive details.  
- **Boundary case:** check empty values, edge extremes, different encodings, repeated requests, expired session states, and equivalent paths/operations.  
- **Telemetry:** confirm policy decision, application log, proxy log, and datastore side effects match correlation ID.  
- **Recheck:** save the minimal script that reproduces the old error and prove the fix does not depend on WAF/rate limit.

## 13. Common Mistakes

- Only check the status code or response string of XML Bombs without verifying side effects and logs.  
- Use a payload with the correct syntax but with the wrong DBMS, browser, framework, protocol, or injection context.  
- Treat UUID, rate limit, WAF, CSP, or general input validation as fixed for another original control.  
- Only fix one route while the same sink/policy is used in other routes.  
- Conclude that a vulnerability exists without saving the source, fixture version, and observable evidence.

## 14. Summary and Checklist

- [ ] Root cause, consequences, and exploitation techniques have been separated.  
- [ ] Actor, role/authentication, trust boundary, technology, and version are clear.  
- [ ] Payload has a unique ID, context, encoding, conditions, expected result, risk, validation, and source.  
- [ ] Code prone to errors/unsafe uses the same framework, version, and use case.  
- [ ] Mandatory controls cannot be replaced with defense-in-depth.  
- [ ] Positive, negative, boundary cases, and telemetry have been retested.  
- [ ] Sensitive technical claims have references in section 17, and all links are only in sections 16–17.  
- [ ] Cleanup is complete; no secrets, real targets, Internet callbacks, or customer data remain.

## 15. Glossary

- **XML Entity (XML Entity)**: Acts as a variable or a shortcut for a longer text segment in the XML document.  
- **DTD (Document Type Definition)**: Defines the document type, used to regulate the grammatical structure and valid entities used in the XML file.  
- **XML Parser**: XML parser, responsible for reading and compiling the XML file into a data structure that the application can understand.  
- **Entity Expansion**: The process of replacing abbreviated entities with their actual text values while processing XML.  
- **Out of Memory (OOM)**: System memory exhaustion error RAM, causing the application or server to crash due to the inability to allocate additional memory.  
- **Billion Laughs**: Popular name for the XML Bomb attack, originating from recursively repeating an entity with the value "lol" up to a billion times.  
- **Defusedxml**: A safe Python library used to replace the default XML parser, automatically preventing XML Bomb attacks and external entity injection.

## 16. Related Lessons and Further Reading

- [XML External Entities](../../05-injection/xxe/) — External entity injection vulnerability XML allows reading system files or performing SSRF instead of causing server resource exhaustion.

## 17. References

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — version/status: current version; accessed: 2026-07-18. 
- **[S2]** CWE-776. https://cwe.mitre.org/data/definitions/776.html — version/status: current version; accessed: 2026-07-18. 
- **[S3]** CWE-400. https://cwe.mitre.org/data/definitions/400.html — version/status: current version; accessed: 2026-07-18. 
- **[S4]** Python XML Processing Modules — XML vulnerabilities. https://docs.python.org/3/library/xml.html#xml-vulnerabilities — version/status: Python 3.x; accessed: 2026-07-18. 
- **[S5]** defusedxml documentation. https://github.com/tiran/defusedxml — version/status: 0.7.1; accessed: 2026-07-18.