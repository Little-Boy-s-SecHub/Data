---
schema_version: 1
id: WEB-A04-DOWNGRADE-ATTACKS
title: "Downgrade Attacks"
slug: downgrade-attacks
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A04:2025
cwe:
  - CWE-327
content_status: technical-review
payload_status: none
last_verified: null
---

# Downgrade Attacks

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain Downgrade Attacks by the root cause instead of just describing the consequences.
- Identify the trust boundary, asset, actor, and necessary conditions for the vulnerability to be exploited.
- Conduct controlled testing in a local lab and distinguish between expected results and false positives.
- Select root controls, implement fixes, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- TLS handshake, supported versions and cipher suite.

- Client/server minimum-version policy and fallback.

- OpenSSL/Nginx setup with lab certificate.

## 3. Background Knowledge

To protect your personal information while moving online, browsers and servers use a "secure pipeline" called the TLS protocol. The process of setting up this pipeline begins with a polite conversation (called the **TLS handshake sequence**). First, your browser sends a greeting (**Client Hello**) along with a list of the encryption languages it understands (cipher suites) and the versions of TLS it supports. The server will politely respond with a server greeting (**Server Hello**), selecting the highest TLS version and the safest cipher that both parties understand to communicate (called cipher negotiation - **cipher negotiation**). [S3]

In modern TLS, asymmetric signatures authenticate the transcript and ephemeral key agreement creates a shared secret; application data is then protected with AEAD symmetric. These details depend on the version and cipher suite, so not every TLS handshake should be described as 'using a public key to encrypt a session key.' [S3]

### Illustration of normal operation (Normal Operation)```python
# Python code demonstrating a secure SSL/TLS client connection that prevents downgrade attacks
import socket
import ssl

hostname = 'www.victim.lab.test'
port = 443

# Create a secure SSL context enforcing strong cryptographic protocols
# We restrict the communication to TLSv1.2 or TLSv1.3 only, disabling outdated versions
context = ssl.create_default_context(cafile="/lab/ca.pem")
context.minimum_version = ssl.TLSVersion.TLSv1_2
context.maximum_version = ssl.TLSVersion.TLSv1_3

# Establish the connection under secure handshake parameters
with socket.create_connection((hostname, port)) as sock:
    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
        # Secure TLS handshake occurs here under the hood
        print(f"Successfully negotiated protocol version: {ssock.version()}")
        print(f"Negotiated cipher suite: {ssock.cipher()[0]}")

        # Safe communication using symmetric encryption begins
        ssock.sendall(b"GET / HTTP/1.1\r\nHost: www.victim.lab.test\r\n\r\n")
```

## 4. Description and Root Cause

A downgrade attack occurs when an actor in the MitM position causes two endpoints that actually support stronger configurations to complete the connection using a weaker version or primitive. The actor cannot simply modify `ClientHello` of a modern TLS handshake and then maintain the connection throughout: transcript/`Finished` and the downgrade sentinel mechanism of TLS 1.3 will detect many forms of interference. A real-world scenario requires an unsafe fallback, out-of-band negotiation, legacy implementation, or specific protocol flaw. [S3]

Non-automatic impact is to 'decode all traffic'. It must be proven that the negotiated primitive has exploitable weaknesses within the correct threat model. TLS 1.0 and 1.1 have been deprecated by IETF; the current minimum baseline is TLS 1.2. [S4]


## 5. Threat Model and Exploitation Conditions

- **Assets:** TLS version and the algorithm/protocol negotiated by the two endpoints.

- **Actor:** legacy peer or logic fallback in fixture; on-path proxy only affects if fallback/negotiation outside of TLS has been controlled and authenticated. [S3]

- **Trust boundary:** TLS terminator Nginx/OpenSSL accepts version/cipher from ClientHello.

- **Necessary condition:** the endpoint still enables weak protocols or fallback is not protected; certificate validation must still be considered.

- **Environment:** OpenSSL 3.x client/server container, TLS 1.0-1.3 fixture, local packet log.

Handshake failure or legacy support does not automatically prove downgrade; it is necessary to prove the session completed at a weaker level than the desired policy. [S1]

## 6. Attack Mechanism

Peer/proxy performs two endpoints negotiation or falls back to version/cipher under policy. The finding requires a completed handshake at a weak level, not just a configuration list with legacy strings. [S1]

## 7. Testing in an Authorized Lab

1. **Setup:** run TLS disposable server with separate legacy/modern configuration and CA lab certificate.  
2. **Baseline:** client negotiates TLS 1.2/1.3 according to the current policy.  
3. **Procedure:** configure legacy client or fallback fixture to require old version/cipher according to the bounded matrix; do not assume a transparent proxy can modify ClientHello and still have the handshake be valid.  
4. **Expected result:** baseline fails to complete weak session; fixed configuration rejects and still allows current client.  
5. **Boundary:** check SNI, ALPN, fallback, and subdomain HSTS as separate issues.  
6. **Cleanup:** delete lab keys/certificates and stop containers.

## 8. Payloads and Scope of Applicability

The blocks below are minimal lab examples according to the context recorded in the annotation. Before use, check the framework/version, encoding, expected result, and risk; only run in an authorized local fixture. Extended payload belongs to `security_cheatsheet.md`; lessons only retain the core examples.

In the lab, use two endpoints pinned to version: baseline only for TLS 1.2/1.3; negative fixture deliberately enables legacy fallback. Confirm the negotiated version/cipher from both client and server logs. Do not use MitM on a real network and do not conclude vulnerability just because the server still supports TLS 1.2. [S3], [S4]

## 9. Vulnerable Code and Secure Code

```configuration
# VULNERABLE BASELINE: legacy versions remain enabled
# ssl_protocols TLSv1 TLSv1.1 TLSv1.2;

# Secure TLS and HSTS configuration in Nginx
server {
    listen 443 ssl http2;
    server_name secure.victim.lab.test;

    ssl_certificate /etc/ssl/certs/app.crt;
    ssl_certificate_key /etc/ssl/private/app.key;

    # Restrict to TLS 1.2 and 1.3 only
    ssl_protocols TLSv1.2 TLSv1.3;

    # TLS 1.2 cipher allowlist for this pinned OpenSSL fixture
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
    ssl_prefer_server_ciphers on;

    # ssl_ciphers does not pin TLS 1.3 suites. Keep the reviewed OpenSSL 3.x
    # defaults, or configure Ciphersuites through a supported ssl_conf_command
    # only after compatibility tests. Verify the negotiated suite in CI. [S6]

    # Enable includeSubDomains only after every subdomain is HTTPS-ready;
    # HSTS preload is a separate operational decision and enrollment process.
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
}
```

## 10. Detection

- Record negotiated protocol/cipher for baseline and fallback path; support legacy that has not self-proved downgrade. [S3]

- Review minimum version at all TLS terminators and client fallback logic. [S3], [S4]

- Collect handshake transcript and policy result; do not turn off certificate validation except in special cases.

## 11. Defense

### Compulsory control

- Turn off TLS 1.0/1.1 and primitive outside the policy at every endpoint/terminator. [S4]

- Do not build fallback yourself; use the existing library with downgrade protection. [S3]

### Defense-in-depth

- Inventory client legacy before upgrading the minimum version.

- Alert when negotiation drops below the expected baseline.

## 12. Retest

- **Positive:** the current client/server negotiates version/cipher in the policy.

- **Negative:** legacy-only peer rejected, no silent fallback.

- **Boundary:** SNI, session resumption, alternate terminator and other clients.

- **Telemetry:** save negotiated version/cipher and policy enforcement points.

## 13. Common Mistakes

- Call all legacy support a exploited downgrade.

- Check a load balancer but overlook the origin/sidecar.

- Turn off certificate validation to do tests and then generalize the results.

- Describe the TLS 1.3 cipher suite according to the structure of the old TLS.

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

- **Downgrade:** connection completed with a lower version/primitive than the policy due to fallback or negotiation being affected. [S3]

- **TLS negotiation:** handshake selects version and common parameters according to the protocol. [S3]

- **Minimum version:** the lowest protocol threshold allowed by the endpoint; TLS 1.0/1.1 has been deprecated. [S4]

## 16. Related Lessons and Further Reading

- [DNS Poisoning](../dns-poisoning/) — See more lessons about DNS Poisoning.

## 17. References

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — version/status: current version; accessed: 2026-07-17.
- **[S3]** RFC 8446 — The Transport Layer Security (TLS) Protocol Version 1.3. https://www.rfc-editor.org/rfc/rfc8446.html — version/date: August 2018; accessed: 2026-07-17.
- **[S4]** RFC 8996 — Deprecating TLS 1.0 and TLS 1.1. https://www.rfc-editor.org/rfc/rfc8996.html — version/date: March 2021; accessed: 2026-07-17.
- **[S6]** Nginx — ngx_http_ssl_module (`ssl_ciphers`, `ssl_conf_command`, `ssl_protocols`). https://nginx.org/en/docs/http/ngx_http_ssl_module.html — version/status: current documentation; accessed: 2026-07-17.