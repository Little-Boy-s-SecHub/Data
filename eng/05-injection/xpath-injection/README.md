---
schema_version: 1
id: WEB-A05-XPATH-INJECTION
title: "XPath Injection"
slug: xpath-injection
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A05:2025
cwe:
  - CWE-643
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# XPath Injection

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain XPath Injection by root cause instead of just describing the consequences. 
- Identify trust boundary, asset, actor, and the necessary conditions for the vulnerability to be exploited. 
- Perform controlled testing in a local lab and distinguish expected results from false positives.
- Select the root control, implement the fix, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- Understand the HTTP request/response flow of XPath Injection scenarios and how to apply input handling across trust boundaries.
- Distinguish between authentication, authorization, and validation.
- Be able to read code/configuration in the language or framework appearing in the example.
- Have a local isolated lab, synthetic data, observable logs, and clear testing permission.

## 3. Background Knowledge

Imagine XML as a family tree or tree-like structure for storing information (such as a list of users and passwords). To search and navigate between the branches of this XML tree, programmers use a query language called XPath (similar to how SQL is used for relational databases). XPath uses intelligent path expressions like `//user[name='admin']` to quickly pinpoint the exact location of the data node needed.

```xml
<!-- users.xml — XML-based user database -->
<users>
  <user>
    <name>admin</name>
    <password>s3cur3P@ss</password>
    <role>administrator</role>
  </user>
  <user>
    <name>guest</name>
    <password>guest123</password>
    <role>viewer</role>
  </user>
</users>
```
User authentication application using XPath query:

```python
# Normal authentication using XPath query
import lxml.etree as ET

tree = ET.parse('users.xml')

# Build XPath to find matching user
query = f"//user[name='{username}' and password='{password}']"
result = tree.xpath(query)

if result:
    print("Login successful")
```

## 4. Description and Root Cause

XPath Injection vulnerabilities occur when a web application directly concatenates user input into an XPath query without any validation or sanitization. An attacker can insert logical operators like `or` or `'` to break the original search logic. Unlike databases SQL that have complex permission layers for each table, XML documents are often just single files without any internal access control mechanisms. Once an attacker successfully injects a malicious XPath statement, they can bypass login authentication without a password, or extract and read all sensitive information contained in the entire XML file.

> **Reference:** technical claims in the lesson are marked with a source; when applying in practice, compare with the version/framework being used: [S1], [S2], [S3], [S4].

## 5. Threat Model and Exploitation Conditions

- **Assets:** XML user record and XPath authentication/search results.  
- **Actor, authentication, and role:** anonymous calling login/search.  
- **Exploitation conditions:** input is concatenated into XPath and modifies predicate or node set.  
- **Browser, proxy, framework, and version:** Java 17 XPath engine on XML aggregate; loopback; must save actual image/package version along with evidence.  
- **Mandatory evidence:** together with correlation ID must concatenate input, determine control, and impact the correct asset; individual status code is not sufficient. [S1]

## 6. Attack Mechanism

For xpath injection, the input is concatenated into the XPath and changes the predicate or node set. The positive case must demonstrate that the input reaches the correct sink and produces the described effect; the negative case must be blocked before any side effect when native control is enabled. The conclusion applies only to the environment pinned in section 5. [S1]

## 7. Testing in an Authorized Lab

1. **Setup:** launch the Java 17 XPath engine on XML compiled; loopback; only load compiled data, enable application/proxy/datastore logs, and attach correlation ID.
2. **Baseline:** send a valid input of the XPath injection use case; save raw request/response, determine the policy and asset state before testing.
3. **Input and operation:** use exactly one core payload in item 8 in the annotated context; change one variable at a time and comply with the request cap.
4. **Expected result:** consider a vulnerable fixture positive only when logs demonstrate the mechanism “input is concatenated into XPath and changes predicate or node set”; secure fixture must block before side effects and boundary input must fail closed.
5. **Cleanup:** delete data, markers, and logs of XPath injection; revoke related sessions/cache, restore snapshot, and confirm no remaining test callbacks/processes.
6. **Safety limits:** run only on loopback/`.lab.test`; do not use real targets, credentials, or data; OOB/DoS/state-changing must have network/CPU/memory/request cap.

## 8. Payloads and Scope of Applicability

The blocks below are minimal lab examples according to the context recorded in the annotation. Before use, check the framework/version, encoding, expected result, and risk; only run in an authorized local fixture. Extended payload belongs to `security_cheatsheet.md`; lessons only retain the core examples.

**Authentication Bypass** — Classic tautology attack similar to SQL Injection:

<!-- payload-id: WEB-A05-XPATH-INJECTION-001 -->
<!-- context: Java 17 XPath login fixture concatenates username/password into a string predicate -->
<!-- prerequisites: synthetic XML users; one request; no token or privileged data returned -->
<!-- encoding: quotes/spaces are UTF-8 form data encoded once; XPath engine receives decoded literal input -->
<!-- expected-result: vulnerable expression selects the designated fixture user; variable-bound query returns no match -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
# Malicious input
username: ' or '1'='1
password: ' or '1'='1

# Resulting XPath query becomes:
//user[name='' or '1'='1' and password='' or '1'='1']
# This always evaluates to TRUE — returns all users
```
**Data Extraction using Boolean-based Blind XPath Injection**:

<!-- payload-id: WEB-A05-XPATH-INJECTION-002 -->
<!-- context: Java 17 XPath fixture exposes a boolean response for a public four-character labCode node -->
<!-- prerequisites: synthetic XML only; maximum four positions by 36 characters; bounded harness -->
<!-- encoding: XPath quotes and substring expression are UTF-8 form data percent-encoded once -->
<!-- expected-result: bounded oracle recovers only LAB1; secure variable binding yields no predicate injection -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
# Test the first character of the public fixture labCode
' or substring(//labCode, 1, 1)='L' or 'a'='b

# The bounded harness tests only four positions against A-Z and 0-9,
# then stops after recovering the documented marker LAB1.
```
**Extract node name using the name() function**:

<!-- payload-id: WEB-A05-XPATH-INJECTION-003 -->
<!-- context: Java 17 XPath fixture tests one known child-node name in synthetic XML -->
<!-- prerequisites: one fixture user and a three-name allowlist; maximum three requests -->
<!-- encoding: XPath name expression is UTF-8 form input encoded once and inserted only by vulnerable route -->
<!-- expected-result: vulnerable boolean differs for the documented node; fixed expression treats the probe as a literal username -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
# Discover node names in the XML structure
' or name(//user[1]/child::*[1])='name' or '1'='2

# Attacker can enumerate the entire XML schema
```

## 9. Vulnerable Code and Secure Code

```python
# === VULNERABLE CODE ===
from lxml import etree

def login_vulnerable(username, password):
    tree = etree.parse('users.xml')
    # DANGER: String concatenation with user input
    query = f"//user[name='{username}' and password='{password}']"
    result = tree.xpath(query)
    return len(result) > 0


# === SECURE CODE ===
from lxml import etree
import re

def login_secure(username, password):
    tree = etree.parse('users.xml')

    # Validate input — allow only alphanumeric characters
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False
    if not re.match(r'^[a-zA-Z0-9@!#_]+$', password):
        return False

    # Use XPath variables for parameterized queries
    # lxml supports XPath variables via the 'variables' parameter
    query = "//user[name=$uname and password=$pwd]"
    result = tree.xpath(query, uname=username, pwd=password)
    return len(result) > 0
```

## 10. Detection

- Log the actor/session, route or operation, object/resource related to XPath Injection, policy results, and correlation ID; do not log secrets or entire tokens. 
- Compare authorization/validation failures with a valid baseline and alert according to behavior chains, not just a single payload chain. 
- Combine application telemetry, reverse proxy, and datastore to verify that the request reached the sink and whether there was any impact. 
- Scanner or WAF alerts are only investigation signals; they are not the sole evidence that a vulnerability exists. [S1]

## 11. Defense

### Compulsory control

- Bind the XPath variable or use a fixed query; do not concatenate input into the expression.
- Apply the same control to all routes, operations, and equivalent processing paths; failure must stop before side effects.

### Defense-in-depth

With XPath Injection, the measures below help reduce blast radius or increase detection capability. Rate limit, UUID unpredictable, WAF, CSP, or general validation cannot be used to replace original controls.

- **Summary**: Use variable binding queries in XPath and validate input characters against a whitelist.  
- **Detailed steps**:  
  - Parameterized XPath queries: Use XPath variable binding instead of string concatenation — similar to prepared statements in SQL.  
  - Input validation: Whitelist allowed characters (alphanumeric), reject special characters `'`, `"`, `/`, `[`, `]`.  
  - Database migration: If the data is important, migrate from XML file to a database with a permissions system.  
  - Least privilege: Limit XPath query scope to only the necessary nodes.  
  - Error handling: Do not expose XPath error messages to the client.

## 12. Retest

- **Positive case:** with XPath Injection, the valid flow still works correctly for the actor and allowed data.  
- **Negative case:** with the same input/resource but an unauthorized actor or context, it is denied without leaking sensitive details.  
- **Boundary case:** test empty values, edge cases, different encodings, repeated requests, expired session states, and equivalent paths/operations.  
- **Telemetry:** confirm policy decision, application log, proxy log, and datastore side effects match correlation ID.  
- **Recheck:** save the minimal scenario reproducing the old error and demonstrate the fix does not depend on WAF/rate limit.

## 13. Common Mistakes

- Only check the status code or response string of XPath Injection without verifying side effects and logs.
- Use payloads with correct syntax but wrong DBMS, browser, framework, protocol, or injection context.
- Consider UUID, rate limit, WAF, CSP, or general input validation as fixes for another root control.
- Only fix one route while the same sink/policy is used on another route.
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

- **XPath**: A query language used to locate and retrieve data from XML documents.
- **XPath Injection**: Injecting malicious XPath code to modify queries and illegally extract XML data.
- **XML Node**: A node representing an element, attribute, or text in an XML document.
- **Statement Stacking**: A technique of stacking multiple statements to execute consecutively (not supported in XPath).
- **Logic Operator**: Logical operators such as AND, OR used in query statements.

## 16. Related Lessons and Further Reading

- [SQL Injection](../sql-injection/) — Structural query code injection vulnerability.

## 17. References

- **[S1]** OWASP WSTG — Testing for XPath Injection. https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/09-Testing_for_XPath_Injection — version/status: latest; accessed: 2026-07-17.
- **[S2]** OWASP. https://owasp.org/www-community/attacks/XPATH_Injection — version/status: current version; accessed: 2026-07-17.
- **[S3]** CWE. https://cwe.mitre.org/data/definitions/643.html — version/status: current version; accessed: 2026-07-17.
- **[S4]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — version/status: current version; accessed: 2026-07-17.