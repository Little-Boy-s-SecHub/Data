---
schema_version: 1
id: WEB-A01-SSRF
title: "Server-Side Request Forgery"
slug: ssrf
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
  - authentication-vs-authorization
owasp:
  - A01:2025
cwe:
  - CWE-918
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Server-Side Request Forgery

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain Server-Side Request Forgery by root cause instead of just describing the consequences.
- Identify trust boundaries, assets, actors, and the necessary conditions for the vulnerability to be exploited.
- Conduct controlled testing in a local lab and differentiate expected results from false positives.
- Select root controls, implement fixes, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- URL parsing, DNS resolution and HTTP redirect.

- Private, loopback, link-local IPv4/IPv6 and egress policy.

- The DNS/cache behavior of the HTTP client is pinned in the fixture.

## 3. Background Knowledge

Imagine your web server as an administrative staff member sitting in the security office of a corporation. This office is inside a strictly secured fence. Outsiders cannot freely enter the internal departments or view the company's database server. However, this administrative staff has a task: "If someone sends a letter requesting to download an image or information from an external website to attach to a record, the staff member will access that link themselves, download the image, and display it on the screen." [S3]

The danger arises when a malicious guest sends a request containing: "Please load the image at address: `http://localhost/admin` or `http://192.168.1.100` (the internal server address)." Since this administrative staff member is sitting *inside* the trusted internal network, he can easily access these local addresses without being blocked by the firewall (known as firewall bypass). He obediently accesses the internal management page or the server containing sensitive data, retrieves information, and sends it back to the external attacker. In the cyber world, the act of tricking a server into performing internal or arbitrary requests is called **SSRF** (Server-Side Request Forgery). [S3]

This threat is directly related to **loopback/private IP** addresses (IP loopback or IP internal). Private IP address ranges (such as `10.0.0.0/8`, `192.168.0.0/16` as defined by RFC 1918), loopback (`127.0.0.1` / `localhost`), and link-local ranges intended for cloud metadata services are only used behind the network boundary. Because the server resides inside this trusted boundary, a server-side HTTP client can send requests directly to internal resources, bypassing perimeter access controls. Attackers exploit this to scan ports, access local administration pages, or steal sensitive metadata tokens. [S3]

Resolve the hostname only once to check IP, then let HTTP client resolve again upon connection **does not** prevent DNS rebinding. A safer control is to remove URL arbitrarily from input whenever possible; if business requires fetching URL, use an egress fetch service to verify all A/AAAA records, pin the destination at the actual connection, disable or revalidate each redirect, limit scheme/port/response, and apply egress ACL independently. [S3]

## 4. Description and Root Cause

The SSRF vulnerability occurs when the application allows users to input an URL address and the server will automatically send a request to that URL without any filters or secure authentication steps. [S3]

This vulnerability is extremely dangerous because it turns your server into a 'spy' or an intermediary proxy for attackers to explore and attack your internal network. Malicious actors can exploit this to scan open network ports within the internal system, access non-public databases, or more seriously, steal access tokens (metadata tokens) from cloud services (such as AWS, Google Cloud, Azure). This could lead to attackers gaining full control over the entire enterprise cloud infrastructure. [S3]


## 5. Threat Model and Exploitation Conditions

- **Assets:** mock metadata and internal services only listening on loopback/container network.

- **Actor:** client controls URL of the fetch function; authentication depends on the route fixture.

- **Trust boundary:** Python requests perform DNS, redirect, and connect from the server.

- **Necessary condition:** URL reaches the sink; allowlist/egress policy is missing; observable response or side effect.

- **Environment:** Python 3.12, mock metadata, DNS fixture IPv4/IPv6, outbound Internet blocked.

Do not use real endpoint metadata: the lab must map fake endpoint metadata and verify egress using mock logs. [S1]

## 6. Attack Mechanism

The server-side fetcher parses URL, resolves DNS, follows redirects and connects using the server's network authority. If validation/egress is not enforced at each hop, URL client may touch mock internal/metadata services. Full-read SSRF returns the target content to the client; semi-blind only reveals differences in state/time; blind SSRF requires a callback or egress log to prove that the server has connected. [S1]

## 7. Testing in an Authorized Lab

1. **Setup:** run the Python fetcher and mock HTTP/DNS in the container network; block all other egress. 
2. **Baseline:** fetch URL allowlist public-fixture successfully.
3. **Actions:** try loopback, IP literal, redirect to mock metadata and IPv6 using a bounded list.
4. **Expected result:** error touches mock internal log; fix blocks before connection or after each redirect.
5. **Boundary:** check DNS changing results, userinfo, mixed encoding, and response size/timeout cap.
6. **Cleanup:** delete callback log, stop container, and confirm egress counter outside fixture is 0.

## 8. Payloads and Scope of Applicability

The payload below only applies to the URL fixture and the safety conditions that have been fully described. Host `.test` must be mapped to a mock service in an isolated container network; the lab must block all outbound Internet. [S3]

<!-- payload-id: WEB-A01-SSRF-001 -->
<!-- context: Python 3.12 link-preview fixture; ssrf-mock.test resolves only inside an isolated container network; destination validation model [S3] -->
<!-- prerequisites: local mock service listens on port 9080; outbound Internet is denied; application accepts an http URL -->
<!-- encoding: ASCII URL with percent-encoding applied by the HTTP client when required -->
<!-- expected-result: vulnerable fixture reaches the mock and its log records marker SSRF_LOCAL_001; secure fixture rejects the destination before connecting -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S3 -->
<!-- last-verified: 2026-07-17 -->
```text
http://ssrf-mock.test:9080/health?marker=SSRF_LOCAL_001
```
Do not replace the host fixture with an internal address, link-local, or real cloud endpoint. Only logging at the mock service proves that the server has made the request; a single differing response content is not enough to conclude SSRF. [S3]

**Blind/Semi-blind SSRF callback probe**

<!-- payload-id: WEB-A01-SSRF-002 -->
<!-- context: Python 3.12 link-preview fixture where callback.lab.test resolves only inside the isolated container network -->
<!-- prerequisites: local callback recorder listens on 127.0.0.1:9081; outbound Internet is denied; application does not return upstream response body -->
<!-- encoding: ASCII URL; marker is a public fixture string and no secret is included -->
<!-- expected-result: blind vulnerable fixture records one callback hit with marker SSRF_BLIND_002; secure fixture rejects destination before connecting and callback log stays empty -->
<!-- risk: oob -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S3 -->
<!-- last-verified: 2026-07-18 -->
```text
http://callback.lab.test:9081/ssrf-blind?marker=SSRF_BLIND_002
```
With semi-blind SSRF, the response body does not leak but latency, status, or error class changes. Evidence still needs to link the request to the egress log or callback recorder in the lab, not relying solely on the error message. [S1]

## 9. Vulnerable Code and Secure Code

```python
# === VULNERABLE CODE ===
import re
from urllib.parse import quote

import requests

def fetch_preview_unsafe(user_url):
    # BAD: the caller controls the destination and redirect chain
    return requests.get(user_url, timeout=5).content


# === SECURE CODE ===
# Users choose a server-side identifier, not a URL. The dedicated fetcher
# enforces DNS/IP policy at connect time and revalidates every redirect hop.
TRUSTED_DESTINATIONS = {
    "public-avatar-cdn": "https://assets.victim.lab.test:8443",
}

def fetch_preview(destination_id, object_id, egress_fetcher):
    base_url = TRUSTED_DESTINATIONS.get(destination_id)
    if base_url is None or re.fullmatch(r"[A-Za-z0-9_-]{1,64}", object_id) is None:
        raise ValueError("Unsupported destination or object identifier")

    # The client selects one opaque identifier, not URL path/query syntax.
    object_path = "/avatars/" + quote(object_id, safe="") + ".png"

    return egress_fetcher.fetch(
        base_url=base_url,
        path=object_path,
        methods={"GET"},
        schemes={"https"},
        ports={8443},
        follow_redirects=False,
        max_response_bytes=2 * 1024 * 1024,
        connect_timeout_seconds=2,
        total_timeout_seconds=5,
    )
```
`egress_fetcher` is a separate security boundary, not a wrapper that just calls back the hostname using a normal HTTP client. Regression tests must cover IPv4/IPv6, mixed records, DNS rebinding and redirecting to loopback/private/link-local/metadata. [S3]

## 10. Detection

- Send URL to mock public and mock internal; confirm the final socket peer along the redirect chain. [S3]

- Review parse, resolve, connect, redirect, and proxy behavior of server-side client. [S3]

- Log normalized destination, resolved IP, connected peer and redirect hop; do not log response secret.

## 11. Defense

### Compulsory control

- Allowlist target/protocol according to business need; resolve and check all IP before connecting, including each redirect. [S3]

- Bind the socket to the verified target or verified connected peer to avoid check-then-connect/DNS rebinding. [S3]

### Defense-in-depth

- Block egress to private/link-local and metadata at the network layer.

- Limit timeout, response size, and redirect count.

## 12. Retest

- **Positive:** URL allowlisted to mock public still works.

- **Negative:** loopback, private, link-local, and schemes outside the policy are blocked.

- **Boundary:** IPv6, decimal/hex IP, redirect chain and DNS answer change.

- **Telemetry:** confirm resolved IP, socket peer, and egress counter.

## 13. Common Mistakes

- Validate the hostname once and then let the client follow redirects on its own.

- Only block IPv4 in dot format.

- Use regex URL instead of the standard parser.

- Consider that network egress/WAF replaces the allowlist in the application.

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

- **SSRF:** untrusted input causes the server to send requests to destinations outside the application policy. [S3]

- **Loopback/link-local:** internal address scope should not be publicly accessible by default. [S3]

- **DNS rebinding:** DNS answer changes between the test step and connection, breaking check-then-connect. [S3]

## 16. Related Lessons and Further Reading

- [XML External Entities](../../05-injection/xxe/) — The XXE vulnerability can be used to perform SSRF network requests directly from the analysis server XML.

## 17. References

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — version/status: current version; accessed: 2026-07-17.
- **[S3]** OWASP Server-Side Request Forgery Prevention Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html — version/status: current version; accessed: 2026-07-17.