---
schema_version: 1
id: WEB-A04-SSL-STRIPPING
title: "SSL Stripping"
slug: ssl-stripping
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A04:2025
cwe:
  - CWE-319
content_status: technical-review
payload_status: none
last_verified: null
---

# SSL Stripping

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain SSL Stripping by root cause instead of just describing the consequence.
- Identify trust boundary, asset, actor, and necessary conditions for the vulnerability to be exploited.
- Conduct controlled testing in a local lab and distinguish expected results from false positives.
- Select root controls, implement the fix, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- HTTP-to-HTTPS redirect, HSTS state and preload.

- The difference between actor on-path and breaking TLS.

- New browser profile and isolated loopback proxy.

## 3. Background Knowledge

Imagine when you access a banking website, you expect a secure HTTPS connection – like sending money in a tightly locked armored car. However, if you just type the host name (for example `victim.lab.test` instead of `https://victim.lab.test`), a user agent without HSTS state might try HTTP first before being redirected to HTTPS. That very first HTTP request is not yet protected by redirect. HSTS only takes effect after the browser receives the header via HTTPS; preload can protect the first visit if the domain has actually been added to the preload list. [S3], [S4]

The core condition is that the actor has an **on-path** position and can modify the initial HTTP traffic. ARP spoofing is just one way to achieve that position in some local networks; it is not a mandatory condition, and the lesson does not perform this technique on real networks. [S3]

The actor maintains the HTTP connection with the browser while being able to open a separate HTTPS connection to the origin. If the browser does not yet have HSTS/preload state and the user proceeds on HTTP, the application bytes sent over the browser–actor leg are cleartext. This is not breaking TLS: the actor–origin connection can still be a separate TLS session authenticated for the origin. [S3], [S5]

### Illustration of normal operation (Normal Operation)```configuration
# Nginx virtual host configuration enforcing HTTPS and HSTS to mitigate SSL Stripping
server {
    listen 80 default_server;
    server_name victim.lab.test www.victim.lab.test;

    # Redirect HTTP to canonical HTTPS, but this response cannot protect the
    # first HTTP request from an on-path attacker.
    return 301 https://victim.lab.test$request_uri;
}

server {
    listen 443 ssl default_server;
    server_name victim.lab.test www.victim.lab.test;

    # SSL Certificate Configuration
    ssl_certificate /etc/ssl/certs/victim.lab.test.crt;
    ssl_certificate_key /etc/ssl/private/victim.lab.test.key;

    # TLS versions; ssl_ciphers below applies to TLS 1.2 in this fixture.
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';

    # HSTS applies only after receipt over HTTPS. Roll out max-age gradually;
    # enable includeSubDomains only after every subdomain is HTTPS-ready.
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
}
```

## 4. Description and Root Cause

SSL stripping in the threat model of the lesson is when an on-path actor keeps the browser on HTTP before HSTS takes effect, while communicating HTTPS separately with the origin. It exploits an unprotected bootstrap HTTP, without downgrading the algorithm inside an already authenticated TLS handshake. [S3], [S5]

Redirect HTTP to HTTPS is needed for compatibility but an on-path actor can modify the first redirect. HSTS provides protection after the browser receives the policy via HTTPS; preload can provide initial protection only if the domain meets the requirements and is actually in the user agent's list. [S3], [S4]

The impact is only confirmed when synthetic sensitive data actually passes through stage HTTP or the operation is modified by the actor. The absence of indicator HTTPS is a signal to the user, but does not replace capture/log proving the marker has passed through cleartext. [S3]


## 5. Threat Model and Exploitation Conditions

- **Assets:** synthetic credentials/cookies in the web lab session.

- **Actor:** on-path proxy between Chromium and victim.lab.test; the user does not yet have HSTS state, which is the main case.

- **Trust boundary:** first HTTP navigation, redirect HTTPS and HSTS state of the browser.

- **Necessary condition:** the user starts with HTTP, the attacker can modify the traffic, and the browser does not yet have HSTS/preload protection.

- **Environment:** Chromium pinned version, Nginx HTTPS loopback, CA lab and local proxy; no ARP real network spoofing.

Redirect 301 does not protect request HTTP; HSTS only applies after being received via HTTPS, unless the preload is already in effect. [S3], [S4]

## 6. Attack Mechanism

On-path proxy keeps the browser connection at HTTP while it itself uses HTTPS to the origin. The browser does not yet have HSTS state and does not know it needs to upgrade; redirects from the server may be modified before reaching the browser. [S3]

## 7. Testing in an Authorized Lab

1. **Setup:** create a new browser profile and an existing profile HSTS; run Nginx/proxy loopback with lab certificate. 
2. **Baseline:** HTTPS is directly valid; profile HSTS is upgraded before sending HTTP. 
3. **Action:** enter victim.lab.test from the new profile and observe the first request through the proxy; do not send real credentials. 
4. **Expected result:** the new profile can send the first HTTP; after HSTS or preload simulation, the browser upgrades internally and the proxy does not see HTTP. 
5. **Boundary:** check includeSubDomains only when all subdomains are HTTPS-ready and distinguish preload enrollment. 
6. **Cleanup:** delete the profile, certificate/key, and proxy capture.

## 8. Payloads and Scope of Applicability

The blocks below are minimal lab examples according to the context recorded in the annotation. Before use, check the framework/version, encoding, expected result, and risk; only run in an authorized local fixture. Extended payload belongs to `security_cheatsheet.md`; lessons only retain the core examples.

In the fixture, the on-path proxy only replaces/redirects synthetic page links and writes harmless markers. It does not use real credentials, does not spoof ARP, and does not claim that the tool can “replace every link”: URL absolutely, dynamic content, HSTS, mixed-content policy, and application logic create their own boundary cases. [S3]

## 9. Vulnerable Code and Secure Code

Baseline error still serves content/credential form via HTTP:```configuration
# VULNERABLE Nginx server for the fixture
server {
    listen 80;
    server_name victim.lab.test www.victim.lab.test;
    location / { proxy_pass http://web_backend; }
}
```
Safer configuration on the same Nginx redirects HTTP to HTTPS and enables HSTS:```configuration
# SECURE Nginx configuration for the same fixture
server {
    listen 80;
    server_name victim.lab.test www.victim.lab.test;
    return 301 https://victim.lab.test$request_uri;
}

server {
    listen 443 ssl;
    server_name victim.lab.test www.victim.lab.test;

    # SSL Configuration (required for server to start)
    ssl_certificate /etc/ssl/certs/victim.lab.test.crt;
    ssl_certificate_key /etc/ssl/private/victim.lab.test.key;

    # Enable includeSubDomains only after every subdomain is HTTPS-ready
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
}
```
Apache VirtualHost configuration equivalent to defense HSTS:```configuration
# Apache virtual host configuration for HSTS
<VirtualHost *:443>
    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/victim.lab.test.crt
    SSLCertificateKeyFile /etc/ssl/private/victim.lab.test.key

    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
</VirtualHost>
```

## 10. Detection

- With the new profile, capture request HTTP at the beginning, redirect and status HSTS; only the cleartext marker proves the impact. [S3]

- Check HSTS on response HTTPS, subdomain scope and actual preload status. [S3], [S4]

- Use browser network/proxy to capture locally; do not spoof the real network with ARP.

## 11. Defense

### Compulsory control

- Serve sensitive flow via HTTPS and deploy HSTS after the host within the scope is ready. [S3]

- Use preload only after the request is fulfilled and the domain is actually added to the list. [S4]

### Defense-in-depth

- Redirect HTTP supports compatibility but does not protect the initial request.

- Secure cookie reduces cookie leakage on the HTTP segment.

## 12. Retest

- **Positive:** HTTPS is valid for operation and HSTS is saved on the profile.

- **Negative:** after HSTS/preload, the browser does not send the HTTP request to the host.

- **Boundary:** new profile, subdomain, expiry, captive portal, and mixed content.

- **Telemetry:** cross-check HSTS state, redirect chain, and packet capture.

## 13. Common Mistakes

- Confirm that the 301 redirect protects the first HTTP request.

- Saying SSL stripping the decoding of session TLS.

- Consider the `preload` token in the header as already in the preload list.

- Use ARP spoofing on a real network to verify.

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

- **On-path actor:** an actor capable of observing or modifying traffic on a network path. [S3]

- **HSTS:** policy received via HTTPS requires the user agent to upgrade/connect to the host using HTTPS within the deadline. [S3]

- **Preload:** the HSTS state is pre-distributed; the header token does not automatically add the domain to the list. [S4]

## 16. Related Lessons and Further Reading

- [DNS Poisoning](../dns-poisoning/) — See more lessons about DNS Poisoning.

## 17. References

- **[S3]** RFC 6797 — HTTP Strict Transport Security. https://www.rfc-editor.org/rfc/rfc6797.html — version/date: November 2012; accessed: 2026-07-17.
- **[S4]** Chromium HSTS Preload — submission requirements and deployment guidance. https://hstspreload.org/ — version/status: current page; accessed: 2026-07-17.
- **[S5]** RFC 8446 — The Transport Layer Security (TLS) Protocol Version 1.3. https://www.rfc-editor.org/rfc/rfc8446.html — version/date: August 2018; accessed: 2026-07-18.