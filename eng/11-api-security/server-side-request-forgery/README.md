---
schema_version: 1
id: WEB-A11-SERVER-SIDE-REQUEST-FORGERY
title: "API Server-Side Request Forgery"
slug: server-side-request-forgery
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
  - network-basics
owasp:
  - API7:2023
cwe:
  - CWE-918
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# API Server-Side Request Forgery

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

- Identify the API endpoint for the URL fetch server provided by the client.
- Distinguish full-read, semi-blind, and blind SSRF.
- Design egress allowlist and safe URL canonicalization.

## 2. Prerequisites

- URL parsing, DNS resolution and redirect.
- Internal metadata service and loopback/private network.
- Logging egress in local lab.

## 3. Background Knowledge

SSRF in API occurs when the backend sends a request to URL instead of the client or to a host controlled by the client. API7:2023 emphasizes that modern API often have webhook, import URL, preview, callback, and integration connector. [S1]

## 4. Description and Root Cause

The root cause is the server-side fetcher lacking an allowlist according to business destination, validating URL before canonicalizing, following a redirect outside the policy or allowing access to internal addresses. [S1]

## 5. Threat Model and Exploitation Conditions

- **Assets:** metadata endpoint, internal admin API, service mesh, cloud credentials. 
- **Actor:** user with permission to call the integration/import endpoint. 
- **Trust boundary:** URL client sends to the fetcher backend. 
- **Necessary condition:** fetcher connects to a destination outside the allowlist or internal. 
- **Environment:** mock HTTP/DNS/metadata only runs on loopback.

## 6. Attack Mechanism

Actor sends URL pointing to an internal destination or lab callback. With full-read SSRF, the response is returned to the client; with blind SSRF, only the callback/egress is logged to prove the server has connected.

## 7. Testing in an Authorized Lab

1. Seed allowlist `https://assets.lab.test`.  
2. Send baseline to a valid destination.  
3. Send URL loopback/private/callback and redirect.  
4. Expect fix to block before DNS/connect or after redirect revalidation.  
5. Cleanup callback log and mock DNS.

## 8. Payloads and Scope of Applicability

**Blind callback probe**

<!-- payload-id: WEB-A11-SERVER-SIDE-REQUEST-FORGERY-001 -->
<!-- context: HTTP/1.1 POST against local import fixture at 127.0.0.1:18080; case: WEB-A11-SERVER-SIDE-REQUEST-FORGERY-001 -->
<!-- prerequisites: callback.lab.test resolves only to loopback mock; outbound Internet blocked -->
<!-- encoding: JSON UTF-8; URL is parsed exactly once by the fixture -->
<!-- expected-result: vulnerable fixture records one loopback callback; fixed fixture rejects destination before connect -->
<!-- risk: oob -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2 -->
<!-- last-verified: 2026-07-18 -->
```http
POST /api/import-url HTTP/1.1
Host: api.victim.lab.test
Content-Type: application/json

{"url":"http://callback.lab.test/ssrf-probe"}
```

## 9. Vulnerable Code and Secure Code

```python
# VULNERABLE: fetches arbitrary client-supplied URL.
def import_url(url):
    return requests.get(url, timeout=2).text

# SECURE: canonicalizes, allowlists and blocks redirects outside policy.
def import_url_secure(url):
    target = canonicalize_url(url)
    if target.host not in {"assets.lab.test"}:
        raise ValueError("destination not allowed")
    return fetch_without_cross_policy_redirect(target)
```

## 10. Detection

- Correlate request ID with DNS/connect log.
- Record final URL after redirect.
- Do not infer SSRF only from accepted URL syntax.

## 11. Defense

### Compulsory control

- Use positive allowlist for business destinations.
- Re-validate after DNS and redirect.
- Block loopback, link-local, private and metadata ranges.

### Defense-in-depth

- Egress proxy, network policy and metadata service hardening.
- Response size/time limits.
- Separate fetcher identity with least privilege.

## 12. Retest

- **Positive:** allowed host works.
- **Negative:** loopback/private/callback blocked.
- **Boundary:** redirect, DNS rebinding, IPv6, encoded host.
- **Telemetry:** no blocked destination connection in fixed fixture.

## 13. Common Mistakes

- Validate string prefix before URL parsing.
- Allow redirect without revalidation.
- Depend only on WAF while backend can still connect internal network.

## 14. Summary and Checklist

- [ ] Fetcher has business allowlist.
- [ ] URL is canonicalized before policy.
- [ ] DNS/connect/redirect telemetry is captured.
- [ ] Blind and full-read cases are separated.

## 15. Glossary

- **Full-read SSRF:** the client sees the response from the destination.
- **Blind SSRF:** the client does not see the response but the server egress is recorded.
- **Egress:** outbound connection from the backend.

## 16. Related Lessons and Further Reading

- [SSRF](../../01-broken-access-control/ssrf/)
- [Cloud SSRF patterns](../../01-broken-access-control/ssrf/)
- [Shadow APIs](../shadow-apis/)

## 17. References

- **[S1]** OWASP API Security Top 10 2023 — API7 Server Side Request Forgery. https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/ — current version; accessed: 2026-07-18.
- **[S2]** CWE-918 — Server-Side Request Forgery. https://cwe.mitre.org/data/definitions/918.html — current version; accessed: 2026-07-18.