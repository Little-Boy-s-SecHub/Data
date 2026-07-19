---
schema_version: 1
id: WEB-A08-WEB-CACHE-DECEPTION
title: "Web Cache Deception"
slug: web-cache-deception
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  []
cwe:
  - CWE-524
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Web Cache Deception

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain Web Cache Deception by root cause instead of just describing the consequences. 
- Identify trust boundary, asset, actor, and necessary conditions for the vulnerability to be exploited. 
- Conduct controlled testing in a local lab and distinguish expected results from false positives. 
- Choose the root control, deploy the fix, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- Understand the HTTP request/response flow in the Web Cache Deception scenario and how to apply input handling across trust boundaries.
- Distinguish between authentication, authorization, and validation.
- Be able to read code/configuration in the language or framework appearing in the example.
- Have a local isolated lab, synthetic data, observable logs, and clear testing permissions.

## 3. Background Knowledge

Imagine your website's hosting server (Origin Server) as a large supermarket selling all kinds of goods. To reduce the load on the main checkout counter and help customers shop faster, the supermarket places a vending machine (Web Cache/CDN) right at the entrance. This machine is programmed very mechanically: "If a customer buys pre-packaged dry goods like candies, soft drinks (equivalent to static resources such as `.css`, `.js`, `.png`, `.jpg`), keep a copy in the machine so the next person can get it immediately without having to queue up and go into the supermarket."  
The way the machine recognizes pre-packaged dry goods is very simple: it only looks at the file extension of the product name (file extension in the path URL).

However, in the supermarket, there is also a mechanism that automatically handles the customer's path called **path normalization**. If a customer wanders into a shelf that does not exist in the form `/account/settings/anything.css`, the supermarket's navigation system will automatically guide them to the nearest parent shelf, `/account/settings` (the shelf displaying sensitive personal account information).  
This combination creates a critical loophole: the vending machine at the entrance sees the tail `.css` and assumes it is 'packaged dry goods' that need to be stored, while in reality what it just stored is the customer's private information page.

```
# How cache decides what to store — based on file extension
Request: GET /static/style.css → Cache says: "This is CSS, CACHE IT" ✓
Request: GET /api/users         → Cache says: "This is dynamic, DON'T CACHE" ✗
Request: GET /account/info.css  → Cache says: "Looks like CSS, CACHE IT" ✓ ← PROBLEM!
```

```python
# Framework path normalization example (Flask/Django behavior)
# Route defined: /account/settings
# Request to: /account/settings/nonexistent.css

# Step 1: Framework looks for route "/account/settings/nonexistent.css"
# Step 2: Route not found → falls back to "/account/settings"
# Step 3: Returns the REAL account settings page (with user data!)
# Step 4: Cache sees ".css" extension → stores the response as static content
```

## 4. Description and Root Cause

The **Web Cache Deception** vulnerability is a sophisticated reverse trick. The attacker does not need to modify data or insert malware into the system. Instead, he merely acts as a cunning "guide." He creates a path URL that looks like a static file (such as `/account/settings/logo.css`) and lures the victim to click on it.

When the victim (who is logged in) clicks on the link, the web server serves the victim's secure personal information page, but the cache in between is tricked by the `.css` suffix and stores a copy of that page.  
After the trap has been triggered, the attacker only needs to access the exact path `/account/settings/logo.css`. At this point, the cache will happily return the victim's sensitive information page that was previously stored without asking for the attacker's password or access permissions.

To distinguish, **Cache Poisoning** is when an attacker tries to inject malicious code into the cache to infect all other users. Meanwhile, **Cache Deception** is tricking the cache into storing the victim's confidential information, which the attacker then comes to "pick up".

> **Reference:** the technical claims in the lesson are marked with a source; when applying in practice, cross-check with the version/framework being used: [S1], [S2], [S3], [S4], [S5].

## 5. Threat Model and Exploitation Conditions

- **Assets:** private response and shared-cache entry. 
- **Actor, authentication, and role:** actor craft URL; logged-in user role downloaded; anonymous re-download. 
- **Exploitation conditions:** cache treats path as static while origin route becomes private dynamic content. 
- **Browser, proxy, framework, and version:** cache/proxy and origin pinned with Chromium/two clients and separate namespace; must record actual image/package version along with evidence. 
- **Mandatory evidence:** must connect input, control decisions, and impact the correct asset with the same correlation ID; individual status code is not enough. [S1]

## 6. Attack Mechanism

For web cache deception, the cache considers the path as static while the origin routes it to private dynamic content. A positive case must prove that the input reaches the correct sink and creates the described impact; a negative case, when origin control is enabled, must be blocked before any side effect. The conclusion only applies to the environment pinned in section 5. [S1]

## 7. Testing in an Authorized Lab

1. **Setup:** launch cache/proxy and origin pinned with Chromium/two clients and a separate namespace; only load synthetic data, enable application/proxy/datastore logging, and attach correlation ID.  
2. **Baseline:** send a valid input of the web cache deception use case; record raw request/response, decide policy and asset state before the test.  
3. **Input and actions:** use exactly one core payload in item 8 in the annotated context; change one variable at a time and comply with the request cap.  
4. **Expected result:** consider the vulnerable fixture as positive only when logs show the mechanism “cache treats path as static while origin routes to private dynamic content”; the secure fixture must block before side effects and boundary input must fail closed.  
5. **Cleanup:** delete data, markers, and logs of web cache deception; revoke related session/cache, revert snapshot, and confirm no remaining callback/test processes.  
6. **Safety limits:** run only on loopback/`.lab.test`; do not use real targets, credentials, or data; OOB/DoS/state-changing must have network/CPU/memory/request cap.

## 8. Payloads and Scope of Applicability

The blocks below are minimal lab examples according to the context recorded in the annotation. Before use, check the framework/version, encoding, expected result, and risk; only run in an authorized local fixture. Extended payload belongs to `security_cheatsheet.md`; lessons only retain the core examples.

**Step 1: The attacker creates a fraudulent URL:**

<!-- payload-id: WEB-A08-WEB-CACHE-DECEPTION-001 -->
<!-- context: candidate paths sent to a pinned cache/origin pair with a unique namespace -->
<!-- prerequisites: bank.lab.test loopback only; synthetic account routes; maximum three probes; cache initially empty -->
<!-- encoding: paths are ASCII except percent cases tested separately; client preserves path bytes without normalization -->
<!-- expected-result: trace identifies only paths where origin serves private route while cache classifies static; no data returned yet -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
# Attacker crafts a URL that:
# 1. Routes to a sensitive page (path normalization)
# 2. Looks like a static file to the cache (.css extension)

https://bank.lab.test/account/settings/logo.css
https://bank.lab.test/my-account/profile.js
https://bank.lab.test/api/user/details/tracking.png
```
**Step 2: Trick the victim into clicking the link:**

<!-- payload-id: WEB-A08-WEB-CACHE-DECEPTION-002 -->
<!-- context: pinned Chromium normal user loads one candidate URL from untrusted.lab.test -->
<!-- prerequisites: synthetic session/profile; one navigation or image load; no email/social delivery -->
<!-- encoding: UTF-8 HTML; href/src absolute .lab.test URL is parsed by browser without additional application decoding -->
<!-- expected-result: victim request reaches the candidate cache key once; secure response remains private/no-store and uncached -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```html
<!-- Attacker sends this link via email, chat, or social engineering -->
<a href="https://bank.lab.test/account/settings/logo.css">
  Click here to verify your account
</a>

<!-- Or embed as invisible image to trigger automatically -->
<img src="https://bank.lab.test/account/settings/logo.css" width="0" height="0">
```
**Step 3: Victim clicks → Cache stores the sensitive page:**

<!-- payload-id: WEB-A08-WEB-CACHE-DECEPTION-003 -->
<!-- context: HTTP/1.1 authenticated request to disposable cache/origin for /account/settings/logo.css -->
<!-- prerequisites: synthetic cookie and profile marker only; unique cache namespace; one victim request -->
<!-- encoding: ASCII request with harness-generated CRLF; cookie is synthetic and path bytes are preserved -->
<!-- expected-result: vulnerable misconfiguration stores a response containing LAB_PRIVATE_PROFILE; secure cache records no shared entry -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```http
# Victim's browser sends (victim is authenticated):
GET /account/settings/logo.css HTTP/1.1
Host: bank.lab.test
Cookie: session=LAB_VICTIM_SESSION

# Origin server: "/account/settings/logo.css" not found
# → Path normalization → serves /account/settings
# Response contains only a synthetic private marker:

HTTP/1.1 200 OK
Content-Type: text/html
Cache-Control: public, max-age=120  # Intentionally unsafe fixture configuration

<html>
<p>LAB_PRIVATE_PROFILE</p>
</html>

# The vulnerable cache rule classifies the .css-looking path as shared and stores it.
```
**Step 4: The attacker accesses the URL as well:**

<!-- payload-id: WEB-A08-WEB-CACHE-DECEPTION-004 -->
<!-- context: HTTP/1.1 unauthenticated verification request uses the same disposable cache key -->
<!-- prerequisites: WEB-A08-WEB-CACHE-DECEPTION-003 completed in same namespace; one request; no real personal/API data -->
<!-- encoding: ASCII request with harness-generated CRLF and no Cookie header -->
<!-- expected-result: vulnerable response contains only LAB_PRIVATE_PROFILE from cache; secure response is 401/redirect without marker -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```http
# Attacker requests the same URL (no authentication needed!)
GET /account/settings/logo.css HTTP/1.1
Host: bank.lab.test

# Cache HIT returns only the stored synthetic marker LAB_PRIVATE_PROFILE.
```
**Advanced variant — Path delimiter confusion:**

<!-- payload-id: WEB-A08-WEB-CACHE-DECEPTION-005 -->
<!-- context: pinned cache/origin versions test semicolon, encoded separator and dot-segment paths separately -->
<!-- prerequisites: synthetic account and unique namespace; maximum three victim plus three verifier requests -->
<!-- encoding: raw client preserves semicolon and percent bytes; each component is decoded exactly once by the documented hop -->
<!-- expected-result: only a parser mismatch observed in fixture is reported; aligned secure routing never creates a shared private entry -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
# Behaviors below apply only to the pinned cache/origin fixtures and must be observed.
# Semicolon delimiter case:
/account/settings;x.css        → fixture origin routes to /account/settings
                                → fixture cache classifies the key as static

# Encoded path separators:
/account/settings%2Flogo.css   → fixture origin and cache normalize differently

# Dot segment normalization:
/static/..%2Faccount/settings  → fixture trace records each hop's normalized path
```

## 9. Vulnerable Code and Secure Code

```python
# === VULNERABLE: Path normalization allows cache deception ===
from flask import Flask, request, session

app = Flask(__name__)

@app.route('/account/<path:subpath>')  # Catches /account/ANYTHING
def account_catchall(subpath):
    # Always returns account data regardless of subpath
    user = get_user(session['user_id'])
    return f"""
    <h1>Account: {user.name}</h1>
    <p>Email: {user.email}</p>
    <p>Balance: ${user.balance}</p>
    """  # DANGEROUS: /account/x.css returns this, CDN caches it!

# === SECURE: Strict routing + proper cache headers ===
@app.route('/account/settings')  # Exact match only
def account_settings_secure():
    user = get_user(session['user_id'])
    response = make_response(render_template('settings.html', user=user))
    # Explicitly prevent caching of user-specific content
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Vary'] = 'Cookie'  # Different response per user session
    return response

@app.errorhandler(404)
def not_found(e):
    """Return 404 for non-existent paths — prevents path normalization abuse"""
    response = make_response("Not Found", 404)
    response.headers['Cache-Control'] = 'no-store'
    return response
```

## 10. Detection

- Log the actor/session, route or operation, object/resource related to Web Cache Deception, policy results, and correlation ID; do not log secrets or entire tokens. 
- Compare authorization/validation failures with a valid baseline and alert according to behavior chains, not just a single payload string. 
- Combine application telemetry, reverse proxy, and datastore to confirm whether the request reached the sink and whether it had any impact. 
- Scanner or WAF alerts are only investigation signals; they are not the sole proof that a vulnerability exists. [S1]

## 11. Defense

### Compulsory control

- Set authenticated response to private/no-store and synchronize path normalization between cache/origin.
- Apply the same control to all routes, operations, and equivalent processing paths; failure must stop before side effects.

### Defense-in-depth

With Web Cache Deception, the following measures help reduce the blast radius or increase detection capability. Rate limit, UUID unpredictable, WAF, CSP, or general validation should not be used as a substitute for original controls.

```nginx
# Nginx — cache ONLY when origin explicitly allows it
proxy_cache_valid 200 0;  # Don't cache by default
# Only cache when origin sends proper cache headers
proxy_cache_use_stale off;
proxy_cache_bypass $http_cache_control;
# Respect origin's Cache-Control header
proxy_ignore_headers "";  # Do NOT ignore any origin headers
```
```python
# Flask — disable path normalization, return 404 for unknown paths
from flask import Flask, abort
app = Flask(__name__)
app.url_map.strict_slashes = True  # Strict URL matching
@app.route('/account/settings')
def account_settings():
    return render_account_page()
# /account/settings/anything.css → 404 (not cached)
```
- **Summary**: Prevent Web Cache Deception by configuring caching based only on Cache-Control headers, returning 404 for non-existent paths, and disabling path normalization.  
- **Detailed steps**:  
  - **Cache only based on `Cache-Control` header**, not on file extension.  
  - **Return 404 for non-existent paths** — disable path normalization/fallback.  
  - **Use `Cache-Control: no-store`** for all pages with user data.  
  - **Add `Content-Type` validation** at CDN — cache only when Content-Type matches extension.  
  - **Remove path parameters** before routing — strip `;`, `%2F`, `..` patterns.

## 12. Retest

- **Positive case:** with Web Cache Deception, the valid flow still works correctly for the actor and allowed data.  
- **Negative case:** same input/resource but unauthorized actor or context is denied without leaking sensitive details.  
- **Boundary case:** test empty values, extreme boundaries, different encodings, repeated requests, expired session state, and equivalent paths/operations.  
- **Telemetry:** confirm policy decision, application log, proxy log, and datastore side effect match correlation ID.  
- **Retest:** keep a minimal scenario reproducing the old error and demonstrate the fix does not depend on WAF/rate limit.

## 13. Common Mistakes

- Only check the status code or response string of Web Cache Deception without verifying side effects and logs. 
- Use a correctly formatted payload but with the wrong DBMS, browser, framework, protocol, or injection context. 
- Consider UUID, rate limit, WAF, CSP, or general input validation as fixed by another original control. 
- Only fix one route while the same sink/policy is used in other routes. 
- Conclude that a vulnerability exists without saving the source, fixture version, and observed evidence.

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

- **Web Cache**: A cache temporarily stores web resources (images, scripts CSS/JS) to serve users faster without having to reload from the origin server. 
- **Origin Server**: The original server, where the source code is stored and the main logic of the web application is processed. 
- **Static Resources**: Files that do not change content per user, such as images, CSS files, JS scripts. 
- **Dynamic Content**: Content that is generated specifically for each user or changes in real time (such as account balances, personal pages). 
- **File Extension**: The part at the end of a file name after the dot (like .css, .js, .png), used to identify the file format. 
- **Path Normalization**: The process of handling URL paths by web frameworks to standardize unusual characters or automatically redirect non-existent sub-paths to the parent page. 
- **Cache-Control**: The header field HTTP used to instruct whether the cache is allowed to store this web page and for how long. 
- **Cache HIT**: The cache state where a copy of the requested resource is found and returned directly to the user without sending a request to the origin server. 
- **CDN (Content Delivery Network)**: A network of content delivery servers located in different geographic areas to speed up data transmission. 
- **Path Delimiter**: Characters (like `/` or `;`) used to separate directories or parameters in the URL address.

## 16. Related Lessons and Further Reading

- [Related lessons in the same folder ](../)

## 17. References

- **[S1]** PortSwigger. https://portswigger.net/web-security/web-cache-deception — version/status: current version; access: 2026-07-18. 
- **[S2]** RFC 9111 — HTTP Caching. https://www.rfc-editor.org/rfc/rfc9111.html — version/date: June 2022; access: 2026-07-18. 
- **[S3]** CWE. https://cwe.mitre.org/data/definitions/524.html — version/status: current version; access: 2026-07-18. 
- **[S4]** Omer Gil. https://omergil.blogspot.com/2017/02/web-cache-deception-attack.html — version/status: current version; access: 2026-07-18. 
- **[S5]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — version/status: current version; access: 2026-07-18.