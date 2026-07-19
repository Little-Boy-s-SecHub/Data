---
schema_version: 1
id: WEB-A05-HTTP-PARAMETER-POLLUTION
title: "HTTP Parameter Pollution (HPP)"
slug: http-parameter-pollution
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A10:2025
cwe:
  - CWE-235
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# HTTP Parameter Pollution (HPP)

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain HTTP Parameter Pollution (HPP) by root cause instead of just describing the consequence.
- Identify the trust boundary, asset, actor, and necessary conditions for the vulnerability to be exploited.
- Conduct controlled testing in a local lab and distinguish expected results from false positives.
- Choose the root control, deploy the fix, and retest with positive, negative, and boundary cases.

## 2. Prerequisites

- Grasp the HTTP request/response flow of the HTTP Parameter Pollution (HPP) scenario and how to apply input handling across trust boundaries. 
- Distinguish between authentication, authorization, and validation. 
- Be able to read code/configuration in the language or framework that appears in the example. 
- Have a local lab isolated, synthetic data, observable logs, and clear testing permissions.

## 3. Background Knowledge

When a request contains two parameters with the same name, the result depends on the parser, API parameter retrieval, middleware, configuration, and specific version. One should not infer from the language name or framework that the system always chooses the first, last, or concatenates all values; the raw request must be checked at each layer of the fixture itself. [S2]

```http
GET /search?category=electronics&category=books HTTP/1.1
Host: shop.victim.lab.test
```

```python
# Illustrative observations; pin and retest the exact versions in the lab:

# A selected PHP fixture may expose the last scalar value through $_GET.

# A selected ASP.NET API may return a comma-joined representation.

# Flask's MultiDict API can select one value or return a list.
# request.args.get("category") = "electronics"           → Takes FIRST occurrence
# request.args.getlist("category") = ["electronics", "books"]  → Returns list

# A selected Servlet container/API can expose one value or all values.
# request.getParameter("category") = "electronics"       → Takes FIRST occurrence
# request.getParameterValues("category") = ["electronics", "books"]

# Express and Rails behavior also depends on the configured query parser and version.
```
Risks arise when two layers in the same stream normalize or choose different values. For example, only valid after the lab demonstrates that the test layer uses the first value while the backend fixture uses the second value; the name of a single technology is not sufficient as evidence. [S2]

## 4. Description and Root Cause

HPP occurs when the same parameter name has multiple values but the layers in the flow select/canonicalize them differently. Only conclude bypass when the log with correlation ID proves that the validation layer and the business layer used different values; do not assign a “first/last” rule based only on the Java name, PHP or WAF. [S2] [S3]

> **Reference:** technical claims in the lesson are marked with a source; when applying in practice, compare with the version/framework being used: [S2], [S3], [S4], [S5].

## 5. Threat Model and Exploitation Conditions

- **Assets:** parameters have been validated and then used in transfer/redirect. 
- **Actor, authentication, and role:** user role has been authenticated for transfer; anonymous for redirect. 
- **Exploitation conditions:** two layers of normalization or choosing different duplicate parameters. 
- **Browser, proxy, framework, and version:** Flask 3.x, reverse proxy pinned and mock OAuth 127.0.0.1; raw HTTP/1.1; must record actual image/package version along with evidence. 
- **Required evidence:** with correlation ID must concatenate input, determine control, and impact the correct asset; individual status code is not sufficient. [S2]

## 6. Attack Mechanism

For HTTP parameter pollution, two normalization layers or selecting a different duplicate parameter. The positive case must prove that the input reaches the correct sink and produces the described effect; the negative case, when the original control is enabled, must be blocked before any side effect. Conclusions only apply to the environment pinned in section 5. [S2]

## 7. Testing in an Authorized Lab

1. **Setup:** launch Flask 3.x, pin the reverse proxy and mock OAuth at 127.0.0.1; raw HTTP/1.1; only load synthetic data, enable application/proxy/datastore logs, and attach correlation ID.
2. **Baseline:** send a valid input for the HTTP parameter pollution use case; record raw request/response, decide policy, and asset status before the test.
3. **Input and operations:** use exactly one core payload from item 8 in the annotated context; change one variable at a time and comply with request cap.
4. **Expected result:** consider a vulnerable fixture positive only when the log proves the mechanism of “two layers of normalization or selecting different duplicate parameters”; secure fixture must block before any side effect, and boundary input must fail closed.
5. **Cleanup:** delete data, markers, and logs of HTTP parameter pollution; revoke related session/cache, revert snapshot, and confirm no test callbacks/processes remain.
6. **Safety limits:** run only on loopback/`.lab.test`; do not use real targets, credentials, or data; OOB/DoS/state-changing must have network/CPU/memory/request cap.

## 8. Payloads and Scope of Applicability

The probes below only apply to the parser and the duplicate order is written from the correct fixture instead of guessing. [S2] [S3]

**Attack 1 — Bypass WAF:**

<!-- claim-source: [S2] [S3] -->
<!-- payload-id: WEB-A05-HTTP-PARAMETER-POLLUTION-001 -->
<!-- context: HTTP/1.1 query parsed by a two-layer fixture whose validator selects the first id and backend selects the last id -->
<!-- prerequisites: synthetic /user record; pinned parsers with duplicate-value behavior captured in logs; one request; no outbound network -->
<!-- encoding: application/x-www-form-urlencoded query; spaces use + and the quote is literal percent-decoded input -->
<!-- expected-result: validator log records id=1 while backend log records the second id; a fixed pipeline rejects duplicate scalar parameters -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S2,S3 -->
<!-- last-verified: 2026-07-17 -->
```http
GET /user?id=allowed&id=blocked-marker HTTP/1.1
Host: victim.lab.test
```

<!-- claim-source: [S2] [S3] -->
<!-- payload-id: WEB-A05-HTTP-PARAMETER-POLLUTION-002 -->
<!-- context: explanatory trace for the pinned two-layer fixture in WEB-A05-HTTP-PARAMETER-POLLUTION-001 -->
<!-- prerequisites: raw query and parsed values from both fixture layers have been captured for the same correlation ID -->
<!-- encoding: quoted text representation; not an executable payload -->
<!-- expected-result: trace displays the distinct first-layer and backend values without claiming universal PHP or WAF behavior -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S2,S3 -->
<!-- last-verified: 2026-07-17 -->
```
Validator sees: id = "allowed"
Backend sees:   id = "blocked-marker"
```
**Attack 2 — Change payment logic:**

<!-- claim-source: [S2] [S3] -->
<!-- payload-id: WEB-A05-HTTP-PARAMETER-POLLUTION-003 -->
<!-- context: HTTP/1.1 baseline POST to a disposable transfer fixture accepting one scalar amount -->
<!-- prerequisites: synthetic alice account and ledger snapshot; authenticated fixture user; exactly one baseline request -->
<!-- encoding: application/x-www-form-urlencoded body generated from UTF-8 ASCII fields -->
<!-- expected-result: fixture records one transfer of 100 USD and one amount value in validation plus execution logs -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S2,S3 -->
<!-- last-verified: 2026-07-17 -->
```http
POST /api/transfer HTTP/1.1
Host: victim.lab.test
Content-Type: application/x-www-form-urlencoded
Content-Length: 32

to=alice&amount=100&currency=USD
```

<!-- claim-source: [S2] [S3] -->
<!-- payload-id: WEB-A05-HTTP-PARAMETER-POLLUTION-004 -->
<!-- context: HTTP/1.1 duplicate amount POST to the disposable transfer fixture -->
<!-- prerequisites: synthetic alice account and ledger snapshot; parser selections captured at validation and execution; exactly one request -->
<!-- encoding: application/x-www-form-urlencoded body preserving both amount fields in order -->
<!-- expected-result: vulnerable fixture logs inconsistent selected amounts; fixed fixture rejects the duplicate and leaves the ledger unchanged -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S2,S3 -->
<!-- last-verified: 2026-07-17 -->
```http
POST /api/transfer HTTP/1.1
Host: victim.lab.test
Content-Type: application/x-www-form-urlencoded
Content-Length: 28

to=alice&amount=100&amount=1
```
**Attack 3 — Server-side HPP via URL building:**

<!-- claim-source: [S2] [S3] -->
<!-- payload-id: WEB-A05-HTTP-PARAMETER-POLLUTION-005 -->
<!-- context: Flask fixture builds an authorization URL for a mock provider at 127.0.0.1:9002 -->
<!-- prerequisites: mock provider is loopback-only and records parsed duplicate parameters; outbound network disabled; one request per case -->
<!-- encoding: callback value is percent-encoded once in the incoming query; the vulnerable example fails to encode it again when composing the provider URL -->
<!-- expected-result: mock provider records two client_id values and their order; the test does not assume which value wins until the provider parser is observed -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S2,S3 -->
<!-- last-verified: 2026-07-17 -->
```python
# Vulnerable code that builds URL from user input
# User controls "callback" parameter
@app.route("/oauth")
def oauth():
    callback = request.args.get("callback")  # Takes first occurrence
    # Test input: /oauth?callback=legit.lab.test%26client_id%3Dsynthetic-client
    # After URL decode: callback = "legit.lab.test&client_id=synthetic-client"

    redirect_url = f"http://127.0.0.1:9002/authorize?callback={callback}&client_id=myapp"
    # Result contains two client_id values. The mock provider log determines
    # which value its pinned parser selects; do not assume a universal rule.
    return redirect(redirect_url)
```
**Attack 4 — Client-Side HPP:**

<!-- claim-source: [S2] [S3] -->
<!-- payload-id: WEB-A05-HTTP-PARAMETER-POLLUTION-006 -->
<!-- context: Chromium fixture renders a duplicate lang value into an HTML href attribute without contextual encoding -->
<!-- prerequisites: local victim.lab.test page with the vulnerable template; synthetic session; no outbound network -->
<!-- encoding: second lang value is URL-encoded in the request, then incorrectly inserted decoded into a double-quoted HTML attribute -->
<!-- expected-result: vulnerable DOM contains an injected script element; fixed template encodes the value and contains only the intended anchor -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S2,S3 -->
<!-- last-verified: 2026-07-17 -->
```html
<!-- Server renders share link using user-controlled parameter -->
<!-- URL: /page?lang=en&lang="><script>document.documentElement.dataset.hpp='client'</script> -->
<a href="/share?utm_source=social&lang="><script>document.documentElement.dataset.hpp='client'</script>">Share</a>
```

## 9. Vulnerable Code and Secure Code

```python
# ❌ VULNERABLE: String concatenation allows HPP
@app.route("/redirect")
def redirect_handler():
    next_url = request.args.get("next")
    # Lab input: /redirect?next=untrusted.lab.test%26admin%3Dtrue
    return redirect(f"/dashboard?next={next_url}&role=user")

# ✅ SECURE: Proper parameter handling with validation
from urllib.parse import urlencode, urlparse

ALLOWED_REDIRECTS = ["dashboard", "profile", "settings"]

@app.route("/redirect")
def redirect_handler():
    next_url = request.args.get("next", "dashboard")

    # Validate against whitelist
    if next_url not in ALLOWED_REDIRECTS:
        next_url = "dashboard"

    # Use urlencode to properly escape values
    params = urlencode({"next": next_url, "role": "user"})
    return redirect(f"/dashboard?{params}")
```

## 10. Detection

- Log the actor/session, route or operation, object/resource, policy result, and correlation ID; do not log secrets or the full token.  
- Compare authorization/validation failures with a valid baseline and alert according to behavior chains, not just a single payload chain.  
- Combine application telemetry, reverse proxy, and datastore to confirm that the request reached the sink and whether or not it had an impact.  
- Scanner or WAF alerts are only investigative signals; they are not the sole evidence that a vulnerability exists. [S2]

## 11. Defense

### Compulsory control

- Canonicalize once and reject duplicates for scalar fields before validation/business logic. 
- Apply the same control to all routes, operations, and equivalent processing paths; failure must stop before any side effect.

### Defense-in-depth

With HTTP Parameter Pollution (HPP), the following measures help reduce the blast radius or increase detection capability. Rate limit, unpredictable UUID, WAF, CSP, or general validation should not be used to replace original controls.

- **Summary**: Strictly control and validate duplicate parameters in the HTTP request to avoid inconsistencies between processing layers.  
- **Detailed steps**:  
  - Clearly choose how to handle duplicate parameters — reject them or only take the first value.  
  - Perform checks and validation at both the WAF layer and the backend layer.  
  - Use a common parser/canonical representation for validation and business logic; test duplicates in the query, form body, and URL built by the server itself. [S2] [S3]

## 12. Retest

- **Positive case:** with HTTP Parameter Pollution (HPP), the valid flow still works correctly for the actor and allowed data.  
- **Negative case:** the same input/resource but unauthorized actor or context should be rejected without leaking sensitive details.  
- **Boundary case:** test empty values, extreme values, different encoding, repeated requests, expired session states, and equivalent paths/operations.  
- **Telemetry:** confirm that policy decisions, application logs, proxy logs, and datastore side effects match correlation ID.  
- **Re-test:** keep a minimal scenario to reproduce the old bug and demonstrate that the fix does not depend on WAF/rate limit.

## 13. Common Mistakes

- Only check the status code or response string of HTTP Parameter Pollution (HPP) without verifying side effects and logs. 
- Use a payload with the correct syntax but wrong DBMS, browser, framework, protocol, or injection context. 
- Treat UUID, rate limit, WAF, CSP, or common input validation as fixed by another control. 
- Only fix one route while the same sink/policy is used in another route. 
- Conclude that a vulnerability exists without saving the source, fixture version, and observable evidence.

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

- **HPP (HTTP Parameter Pollution)**: HTTP parameter pollution by sending multiple parameters with the same name.  
- **WAF (Web Application Firewall)**: Firewall protecting web applications from common attacks.  
- **Query String**: The parameter part that comes after the question mark on URL.  
- **Backend**: The server system that processes data and the underlying logic of the website.  
- **Canonicalization**: Rules for converting multiple input representations into a single form before validation and business processing. [S2] [S3]

## 16. Related Lessons and Further Reading

- [SQL Injection](../sql-injection/) — Command injection attack SQL via parameters.

## 17. References

- **[S2]** OWASP. https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution — version/status: current version; accessed: 2026-07-17.
- **[S3]** CWE. https://cwe.mitre.org/data/definitions/235.html — version/status: current version; accessed: 2026-07-17.
- **[S4]** Original Paper. https://owasp.org/www-pdf-archive/AppsecEU09_CarssoniDiPaola_v0.8.pdf — version/status: current version; accessed: 2026-07-17.
- **[S5]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — version/status: current version; accessed: 2026-07-17.