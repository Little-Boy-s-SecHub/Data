---
schema_version: 1
id: WEB-A02-HOST-HEADER-POISONING
title: "Host Header Poisoning"
slug: host-header-poisoning
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A05:2025
cwe:
  - CWE-644
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Host Header Poisoning

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain Host Header Poisoning by the root cause instead of just describing the consequences. 
- Identify the trust boundary, asset, actor, and necessary conditions for the vulnerability to be exploitable. 
- Conduct controlled testing in a local lab and differentiate expected results from false positives. 
- Select the root control, implement the fix, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- HTTP authority via `Host`/`:authority` and virtual hosting.

- Reverse-proxy trusted headers and canonical public origin.

- Flow to create reset URL via local mail catcher.

## 3. Background Knowledge

Imagine you are sending an express letter through the post office. On the front of the letter, the post office requires you to clearly fill in the information in the "Domain/Recipient Address" field (this is exactly the **Host Header**). The post office uses this information field to know which building to deliver the letter to. However, if the postal staff are too naive, when the letter arrives, they use the address you wrote by hand in the "Host Header" field to print on all response documents, money transfer receipts, or appointment slips for the building without checking whether that address belongs to their official branch system. An attacker could fill in a forged address in this field, tricking the post office into sending important responses containing confidential information straight to their mailbox. [S3]

In the HTTP protocol, the **Host Header** is a required header starting from version HTTP/1.1. When you access a website, the browser automatically sends this header to inform the server which domain you want to access. This allows a single physical server to run multiple websites simultaneously (known as **Virtual Hosting**). The web server (such as Nginx or Apache) reads the Host Header to route your request to the correct directory containing the source code. The vulnerability occurs when a web application fully trusts the value of the Host Header sent by the user to automatically generate absolute links (such as password reset links, account activation links) without re-verifying it. [S3]

```configuration
# Nginx configuration for secure virtual hosting

# 1. Default server block to reject any unrecognized Host headers
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _; # Match any request that does not match other blocks
    return 444; # Connection closed without response (mitigates scanning and poisoning)
}

# 2. Main virtual host configuration for the legitimate application domain
server {
    listen 80;
    server_name app.victim.lab.test www.app.victim.lab.test; # Explicitly whitelisted domains

    location / {
        # Forward canonical values; strip client-supplied forwarding metadata.
        proxy_set_header Host app.victim.lab.test;
        proxy_set_header X-Forwarded-Host app.victim.lab.test;
        proxy_set_header Forwarded "";
        proxy_pass http://localhost:8080;
    }
}
```

## 4. Description and Root Cause

**Host Header Poisoning** vulnerability occurs when a web application blindly trusts the value of the Host header in a request HTTP to generate links or execute system logic. Since this header is sent by the client and can be completely modified by an attacker, this is an extremely dangerous configuration weakness. [S3]

The attacker can change the Host from `app.victim.lab.test` to `callback.lab.test` when sending a password recovery request for a synthetic account. The vulnerable server still processes the request, and the sink mail receives a poisoned link like `https://callback.lab.test/reset?token=LAB_TOKEN`. If the user follows the link, the token could be sent to an untrusted origin; the fixture only records a local marker, not using real tokens or emails. [S3]


## 5. Threat Model and Exploitation Conditions

- **Assets:** reset URL synthetic and route to a valid virtual host.

- **Actor:** an unauthenticated client can send Host/X-Forwarded-Host to the lab reverse proxy.

- **Trust boundary:** Nginx/application builds absolute URL from forwarded host.

- **Necessary condition:** proxy trusts client header or the application does not use canonical origin; email sink records the generated link.

- **Environment:** Nginx 1.26 and mail catcher loopback, fixed TLS termination, does not send Internet email.

Response 200 with an unknown Host is not enough; must prove that sensitive link/caching/routing contains an untrusted host. [S1]

## 6. Attack Mechanism

Proxy transfers Host/forwarded-host controlled by the client and the application uses that value to create an absolute reset URL or cache key. The email/cache sink therefore contains an untrusted origin. [S1]

## 7. Testing in an Authorized Lab

1. **Setup:** run Nginx, app, and mail catcher loopback; seed synthetic account.  
2. **Baseline:** Canonical host generates reset link `app.victim.lab.test`.  
3. **Actions:** change Host and forwarded-host for each request; record raw request and email sink.  
4. **Expected result:** bug version generates callback.lab.test link; fix by rejecting host or using canonical origin.  
5. **Boundary:** test port, multiple Hosts, absolute-form and trusted proxy configuration.  
6. **Cleanup:** delete token/email fixture and stop services.

## 8. Payloads and Scope of Applicability

The request below has valid framing and only uses synthetic data. Only send the request to Nginx/app/mail catcher on loopback or isolated container network; do not send emails or requests to the Internet. [S3]

<!-- payload-id: WEB-A02-HOST-HEADER-POISONING-001 -->
<!-- context: Nginx 1.26 password-reset fixture with a loopback mail catcher; callback.lab.test is a local reserved-name fixture; HTTP authority model [S3] -->
<!-- prerequisites: synthetic learner account exists; vulnerable app builds absolute reset URLs from Host; no outbound email or network access -->
<!-- encoding: ASCII HTTP/1.1 request; application/x-www-form-urlencoded body is exactly 24 bytes -->
<!-- expected-result: vulnerable mail sink stores a reset URL with host callback.lab.test; secure fixture rejects the Host or uses its configured canonical origin -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S3 -->
<!-- last-verified: 2026-07-17 -->
```http
POST /password-reset HTTP/1.1
Host: callback.lab.test
Content-Type: application/x-www-form-urlencoded
Content-Length: 24
Connection: close

email=learner%40lab.test
```
Only the content in the local sink mail can be used as evidence. The response is successful, but resetting URL still uses the canonical origin, which does not prove Host Header Poisoning. [S3]

## 9. Vulnerable Code and Secure Code

```configuration
# VULNERABLE Nginx virtual host: accepts arbitrary Host and forwards it
server {
    listen 80 default_server;
    server_name _;
    location / {
        proxy_set_header Host $http_host;
        proxy_pass http://backend_pool;
    }
}

# SECURE Nginx configuration for the same backend
# 1. Default server block to reject unrecognized hostnames
server {
    listen 80 default_server;
    server_name _;
    return 444; # Terminate connection immediately
}

# 2. Virtual host config for the authorized domain
server {
    listen 80;
    server_name app.victim.lab.test www.app.victim.lab.test;

    location / {
        proxy_set_header Host app.victim.lab.test;
        proxy_set_header X-Forwarded-Host app.victim.lab.test;
        proxy_set_header Forwarded "";
        proxy_pass http://backend_pool;
    }
}
```

## 10. Detection

- Send valid/incorrect authority then check URL saved in the mail sink, not just the response. [S3]

- Review the place where the application builds absolute URL from Host or forwarded headers and configure trusted proxy. [S3]

- Log received authority, canonical origin, and reject branch; do not log reset token.

## 11. Defense

### Compulsory control

- Build URL sensitive from the canonical origin with pre-configured settings, not from untrusted authority. [S3]

- Validate `Host`/`:authority`; only trust forwarded headers from identified proxies. [S3]

### Defense-in-depth

- Reset tokens must be single-use, short-lived, and correctly bound to the account.

- The monitoring authority only supports detection.

## 12. Retest

- **Positive:** valid authority creates URL canonical.

- **Negative:** unknown host is rejected or does not affect URL sending mail.

- **Boundary:** absolute-form, port, duplicate Host and proxy chain.

- **Telemetry:** cross-check ingress authority, app decision, and mail sink.

## 13. Common Mistakes

- Direct message `Host` to create a reset link.

- Message `X-Forwarded-Host` from all clients.

- Only validate at the proxy, but the app still has direct access routes.

- Only look at the response without checking URL in the side channel.

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

- **Authority:** HTTP/1.1 is represented by `Host`; HTTP/2/3 uses pseudo-header `:authority`. [S3]

- **Canonical origin:** scheme, host, and port as configured by the application to make the origin publicly trusted. [S3]

- **Absolute URL:** URL contains scheme and authority instead of just a relative path. [S3]

## 16. Related Lessons and Further Reading

- [Clickjacking](../clickjacking/) — See more lessons about Clickjacking.

## 17. References

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — version/status: current version; accessed: 2026-07-17.  
- **[S3]** RFC 9110 — HTTP Semantics, Section 7.2 Host and `:authority`. https://www.rfc-editor.org/rfc/rfc9110.html#section-7.2 — version/date: June 2022; accessed: 2026-07-18.