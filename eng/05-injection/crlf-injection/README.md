---
schema_version: 1
id: WEB-A05-CRLF-INJECTION
title: "CRLF Injection"
slug: crlf-injection
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A05:2025
cwe:
  - CWE-93
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# CRLF Injection

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain CRLF Injection by root cause instead of just describing the consequences. 
- Identify the trust boundary, asset, actor, and necessary conditions for the vulnerability to be exploited. 
- Conduct controlled testing in a local lab and distinguish expected results from false positives. 
- Select root controls, implement the fix, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- Able to read HTTP/1.1 start-line, field-line, header-section boundary, and `Content-Length` in raw byte form. 
- Understand URL percent-decoding and know how to accurately determine which component is decoded once or multiple times. 
- Differentiate HTTP header serialization from newline used as a log text record boundary. 
- Have a raw-socket fixture and local reverse proxy, without connecting to the target or using shared cache.

## 3. Background Knowledge

In HTTP/1.1, the start-line and each field-line end with CRLF; a blank line ends the header section. Therefore, CR/LF are not arbitrary valid data inside field values. Log text may also use a newline as a record boundary, but that is a separate format and must be checked independently of HTTP framing. [S5]

```http
# Normal HTTP response structure
HTTP/1.1 200 OK\r\n
Content-Type: text/html\r\n
Set-Cookie: session=abc123\r\n
\r\n
<html>...</html>
```
In web applications, redirect often takes URL from user input:

```python
# Normal redirect implementation in Flask
from flask import Flask, redirect

app = Flask(__name__)

@app.route('/redirect')
def do_redirect():
    # User-supplied destination used in Location header
    dest = request.args.get('url', '/')
    return redirect(dest)
```

## 4. Description and Root Cause

The root cause is that the decoded data was written into the field-line or raw protocol stream without being rejected by the core CR/LF. The impact may stop at a secondary header or, in a specific framing/caching sequence, create response splitting; XSS, cache poisoning, or session fixation should not be assumed by default just from the two bytes CRLF. [S1] [S5]

## 5. Threat Model and Exploitation Conditions

- **Assets:** framing HTTP response, header and cache/browser status behind.

- **Actor, authentication, and role:** the user who is not logged in controls the redirect/header parameter.

- **Exploitation conditions:** CR/LF after decoding goes into the header and creates a header or response boundary unintentionally.

- **Runtime:** Python 3.12 fixture self-serializes HTTP/1.1; raw socket receives bytes and Chromium only tests rendering.

- **Evidence:** save raw responses on both proxies; must see CRLF create an independent field-line. [S1] [S5]

## 6. Attack Mechanism

The fixture is prone to parameter decode errors once and then directly concatenates into fields `Location`; CRLF, thus ending the current field and opening a new field. The fix only accepts redirect paths from a fixed mapping table and rejects CR/LF before serialization. Raw octets must be analyzed because the client or proxy may incorrectly normalize the response framing. [S1] [S5]

## 7. Testing in an Authorized Lab

1. **Setup:** launch the Python 3.12 fixture to self-serialize HTTP/1.1 after a pinned local reverse proxy; use raw socket to collect the response and only open Chromium in a separate test rendering.  
2. **Baseline:** send a valid input of the crlf injection use case; save raw request/response, decide on policy and asset state before testing.  
3. **Input and actions:** use exactly one core payload in item 8 in the annotated context; change only one variable at a time and comply with the request cap.  
4. **Expected result:** consider a fixture vulnerable as positive only when logs prove the mechanism “CR/LF after decoding goes into the header and creates an unintended header or response boundary”; a secure fixture must block before side effects and boundary input must fail closed.  
5. **Cleanup:** delete crlf injection data, markers, and logs; reclaim related session/cache, revert snapshot, and confirm no callbacks/processes remain.  
6. **Safety limits:** run only on loopback/`.lab.test`; do not use real targets, credentials, or data; OOB/DoS/state-changing must have network/CPU/memory/request caps.

## 8. Payloads and Scope of Applicability

The probes below require comparing the raw response byte by byte and exactly once URL-decode. [S1] [S5]

**HTTP Response Splitting** — Attacker inserts CRLF into the redirect parameter to inject a new header:

<!-- claim-source: [S1] [S5] -->
<!-- payload-id: WEB-A05-CRLF-INJECTION-001 -->
<!-- context: HTTP/1.1 redirect fixture reflects decoded url into Location -->
<!-- prerequisites: raw response capture on loopback; synthetic cookie name lab_admin; one request; no browser session -->
<!-- encoding: %0d%0a is decoded once to CRLF; spaces use %20; harness generates request framing -->
<!-- expected-result: vulnerable raw response has a separate Set-Cookie lab_admin header; fixed route rejects CR/LF -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S5 -->
<!-- last-verified: 2026-07-17 -->
```
# Attack URL — injecting Set-Cookie header via CRLF
https://victim.lab.test/redirect?url=%0d%0aSet-Cookie:%20lab_admin=true

# The server generates this malformed response:
HTTP/1.1 302 Found\r\n
Location: \r\n
Set-Cookie: lab_admin=true\r\n    <-- Injected header
\r\n
```
**Log Injection** — The attacker inserts a newline to create a fake log entry:

<!-- claim-source: [S3] -->
<!-- payload-id: WEB-A05-CRLF-INJECTION-002 -->
<!-- context: UTF-8 username written as one structured log field by the authentication fixture -->
<!-- prerequisites: synthetic admin username; isolated log file; one failed login; no SIEM or production log -->
<!-- encoding: newline is the single LF byte 0x0a inside the decoded field; structured logger must JSON-escape it -->
<!-- expected-result: vulnerable text log spans two physical entries; structured log remains one event with escaped newline -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S3 -->
<!-- last-verified: 2026-07-17 -->
```
# Malicious username input for log injection
username = "admin\nINFO: Login successful for user admin from 10.0.0.1"

# Log file now shows fake entry:
# WARN: Failed login for user admin
# INFO: Login successful for user admin from 10.0.0.1
```

## 9. Vulnerable Code and Secure Code

```python
# Python 3.12 raw HTTP/1.1 teaching fixture

# === VULNERABLE CODE ===
def build_redirect_vulnerable(destination: str) -> bytes:
    # DANGER: decoded input changes the serialized header section
    response = (
        "HTTP/1.1 302 Found\r\n"
        f"Location: {destination}\r\n"
        "Content-Length: 0\r\n"
        "Connection: close\r\n\r\n"
    )
    return response.encode("ascii")


# === SECURE CODE ===
REDIRECTS = {
    "home": "/",
    "profile": "/profile",
}

def build_redirect_secure(destination_id: str) -> bytes:
    # Map an opaque identifier to a server-owned path
    try:
        destination = REDIRECTS[destination_id]
    except KeyError as exc:
        raise ValueError("Unknown redirect destination") from exc

    response = (
        "HTTP/1.1 302 Found\r\n"
        f"Location: {destination}\r\n"
        "Content-Length: 0\r\n"
        "Connection: close\r\n\r\n"
    )
    return response.encode("ascii")
```

## 10. Detection

- Find a method to concatenate strings into the raw response, write the API header yourself, and decode the input multiple times.

- Collect raw response on both sides of the proxy; count field-line, header boundary, and `Content-Length`.

- With log injection, LF in the username must still be within an event that has an escaped structure.

- Distinguish application rejection, proxy rejection, and client receiving new fields; only the last case confirms injection.

## 11. Defense

### Compulsory control

- Do not self-serialize headers from user data; use the framework/runtime's API header with checks CR/LF.

- With redirect, map destination ID to a fixed path and reject CR/LF instead of stripping. [S1] [S2]

### Defense-in-depth

- Configure the proxy to reject invalid response framing and not cache error responses from fixtures.

- Structured logging so that newlines in data fields are escaped; limit the length of headers and log fields.

- Monitor runtime instances rejecting headers containing control characters. WAF may add signals but does not replace API safe serialization. [S1] [S3]

## 12. Retest

- **Positive case:** destination ID `profile` correctly creates one field `Location: /profile` and one header-section boundary. 
- **Negative case:** input containing `%0d%0aSet-Cookie` is rejected after one decode; raw response does not have field `Set-Cookie` beyond the baseline. 
- **Boundary case:** test single CR, single LF, literal CRLF, uppercase/lowercase percent-encoding, double-encoding, and input passing through one or two proxies. 
- **Telemetry:** compare bytes from application/proxy/client and confirm newline logs remain in a structured event. 
- **Regression:** check all helpers creating `Location`, `Set-Cookie`, download filenames, and log text, because these sinks have different output rules.

## 13. Common Mistakes

- Only searching for the string `%0d%0a` before URL decoding may miss other representations, or decode twice outside the contract.

- Delete CR/LF from the destination and then continue to redirect, accidentally turning an incorrect input into another URL instead of fail closed.

- Using browser devtools as the only evidence; the browser and proxy can discard or normalize invalid responses.

- Mixing log injection with HTTP response splitting even though the two sinks use different record boundaries and serialization sets.

- It is inferred to be XSS or cache poisoning when it has not been proven that field/body injection is accepted by downstream. [S1] [S5]

## 14. Summary and Checklist

- [ ] Raw octets have been saved before and after the proxy, not just browser screenshots. 
- [ ] The number of percent-decodings and the position of the field value are recorded clearly in the payload context. 
- [ ] The fix uses destination ID because the server maps and rejects control characters. 
- [ ] CR, LF, CRLF, double-encoding, and proxy boundaries are all retested separately. 
- [ ] Log injection is verified by events with structure, separated from response splitting. 
- [ ] Do not infer XSS, cache poisoning, or session fixation without downstream evidence.

## 15. Glossary

- **CRLF**: Line break characters (Carriage Return + Line Feed), denoted as `\r\n`.
- **HTTP Response Splitting**: An HTTP response splitting attack by inserting CRLF to create a forged response.
- **Session Fixation**: A session fixation attack, where an attacker forces the victim to use a predefined ID session to later hijack the account.
- **Cache Poisoning**: Poisoning the proxy or browser cache to deliver fake content.
- **Log Injection**: Untrusted data altering the boundaries or structure of log records; this sink is different from HTTP response splitting. [S3] [S5]

## 16. Related Lessons and Further Reading

- [Web Cache Poisoning](../../08-data-integrity-failures/web-cache-poisoning/) — A vulnerability of web cache poisoning, usually exploiting the technique of injecting headers through CRLF Injection to poison the cache response.

## 17. References

- **[S1]** OWASP WSTG — Testing for HTTP Response Splitting. https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/15-Testing_for_HTTP_Response_Splitting — version/status: latest; accessed: 2026-07-17. 
- **[S2]** OWASP. https://owasp.org/www-community/vulnerabilities/CRLF_Injection — version/status: current version; accessed: 2026-07-17. 
- **[S3]** CWE. https://cwe.mitre.org/data/definitions/93.html — version/status: current version; accessed: 2026-07-17. 
- **[S5]** RFC 9112 — HTTP/1.1, Sections 2 and 11.1. https://www.rfc-editor.org/rfc/rfc9112.html — version/status: RFC 9112; accessed: 2026-07-18.