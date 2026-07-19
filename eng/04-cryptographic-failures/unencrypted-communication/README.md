---
schema_version: 1
id: WEB-A04-UNENCRYPTED-COMMUNICATION
title: "Unencrypted Communication"
slug: unencrypted-communication
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

# Unencrypted Communication

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain Unencrypted Communication by root cause instead of just describing the consequences.
- Identify trust boundaries, assets, actors, and the necessary conditions for the vulnerability to be exploited.
- Perform controlled testing in a local lab and distinguish expected results from false positives.
- Select the root control, implement the fix, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- HTTP cleartext, HTTPS and TLS certificate/hostname validation.

- Application data is different from network metadata.

- Packet capture in the lab namespace with CA synthetic.

## 3. Background Knowledge

Imagine sending information over the Internet like sending paper letters. If you use an unencrypted protocol (like HTTP usually), your letter will be sent without an envelope, and anyone standing along the way can easily read the entire contents inside (**cleartext**). [S5]

In practice, when you connect to a public Wi-Fi network at a cafe, an attacker can use techniques like **ARP Spoofing** to trick your device into sending all messages through their machine before reaching the Internet. There, they only need to run a tool called a **packet sniffer** (similar to an automatic mail scanner) to capture all your raw data: from passwords and bank accounts to the content of private messages. [S5]

HTTPS uses TLS to negotiate parameters, establish shared keying material, authenticate the server (and optionally the client), and then protect application records using authenticated encryption. In TLS 1.3, the handshake should not generally be described as “public key session encryption”: key exchange, signatures, and AEAD have separate roles, while details depend on the version/cipher suite. Certificate and hostname validation are conditions for the client to bind the TLS channel to the correct origin. [S5]

### Illustration of normal operation (Normal Operation)```python
# Python client showing secure HTTPS connection using standard libraries
import urllib.request
import ssl

def fetch_secure_data(url):
    # Create a default secure SSL context that enforces certificate validation
    # and secure TLS configuration, protecting against cleartext sniffing
    context = ssl.create_default_context()

    try:
        # Making a secure request over HTTPS (TLS encryption)
        with urllib.request.urlopen(url, context=context) as response:
            html = response.read()
            print(f"Successfully retrieved secure payload. Status: {response.status}")
            return html
    except ssl.SSLError as e:
        print(f"SSL/TLS handshake or certificate verification failed: {e}")
        return None

# Normal operation: Fetching data securely over HTTPS
target_url = "https://service.lab.test:8443/fixture"
secure_content = fetch_secure_data(target_url)
```

## 4. Description and Root Cause

The "Unencrypted Communication" vulnerability occurs when an application transmits sensitive user information (such as passwords, session cookies, card information) over unsecured protocols (such as raw HTTP, FTP). [S5]

The greatest danger of this vulnerability is that it swings wide open the door for any bad actor on the same internal network (or on the Internet transmission) to easily spy on and steal your data without much effort to crack it. If your login session cookie is stolen, an attacker can impersonate you to log into the account immediately without needing to know the password. [S5]


## 5. Threat Model and Exploitation Conditions

- **Assets:** synthetic credential/cookie/marker on the application channel.

- **Actor:** on-path observer in the lab network namespace; does not sniff Wi-Fi or real networks.

- **Trust boundary:** client Python/browser connects HTTP/FTP or TLS to the Nginx service.

- **Necessary condition:** sensitive data passes through plaintext or TLS validation is disabled; public metadata does not automatically generate findings. [S5]

- **Environment:** Python 3.12, Nginx/OpenSSL container, CA lab and local packet capture.

Only conclude when the capture reads the plaintext marker; HTTPS with certificate validation must make the capture only see ciphertext/metadata. [S1]

## 6. Attack Mechanism

The client sends application bytes directly over the HTTP/plaintext protocol, so an on-path observer can read the marker. With TLS authenticated, application bytes are protected, and a certificate/hostname mismatch causes the client to fail closed. [S1]

## 7. Testing in an Authorized Lab

1. **Setup:** run HTTP and HTTPS fixtures in the network namespace, seed marker LAB_CREDENTIAL, and enable limited capture.  
2. **Baseline:** urllib with default SSL context accesses service.lab.test using CA lab.  
3. **Action:** send marker via HTTP fixture then HTTPS fixture; do not use real secrets.  
4. **Expected result:** marker seen in HTTP capture but not in TLS application data; invalid certificate is rejected by client.  
5. **Boundary:** check redirect, mixed content, proxy termination, and separate TLS version.  
6. **Cleanup:** delete pcap/key/marker and stop namespace.

## 8. Payloads and Scope of Applicability

The blocks below are minimal lab examples according to the context recorded in the annotation. Before use, check the framework/version, encoding, expected result, and risk; only run in an authorized local fixture. Extended payload belongs to `security_cheatsheet.md`; lessons only retain the core examples.

The attacker is on the same local network segment as the victim (such as a public Wi-Fi network) and performs techniques like spoofing ARP packets (ARP Spoofing) to trick the router into sending the victim's network traffic through the attacker's machine. Using packet-sniffing tools, the attacker can easily extract sensitive information from unencrypted HTTP packets being transmitted without any complex decryption operations. [S5]

## 9. Vulnerable Code and Secure Code

```configuration
# VULNERABLE Nginx server: application data is served over cleartext HTTP
server {
    listen 80;
    server_name victim.lab.test www.victim.lab.test;
    location / { proxy_pass http://web_backend; }
}
```

```configuration
# SECURE Nginx server for the same application
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name victim.lab.test www.victim.lab.test;
    # Redirect to the specific, hardcoded host to prevent Host Header Injection
    return 301 https://victim.lab.test$request_uri;
}

server {
    listen 443 ssl http2 default_server;
    listen [::]:443 ssl http2 default_server;
    server_name victim.lab.test www.victim.lab.test;

    ssl_certificate /etc/ssl/certs/victim.lab.test.crt;
    ssl_certificate_key /etc/ssl/private/victim.lab.test.key;

    # TLS versions; ssl_ciphers below applies to TLS 1.2 in this fixture.
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA256';

    # Keep reviewed OpenSSL TLS 1.3 defaults or configure its Ciphersuites
    # separately through a supported API; verify negotiated suites in CI.

    # Roll out HSTS after HTTPS readiness; preload is a separate opt-in program.
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
}
```

## 10. Detection

- Send the marker via HTTP and HTTPS and then compare packet capture; only readable plaintext is considered evidence. [S5]

- Review URL scheme, TLS validation, internal hop and client error handling. [S5]

- Do not capture real credentials or production keys.

## 11. Defense

### Compulsory control

- Protect sensitive data with TLS authenticated on all necessary hops; fail closed when certificate/hostname is wrong. [S5]

- Remove cleartext protocol from flows containing credentials, sessions, or sensitive data. [S5]

### Defense-in-depth

- HSTS supports the browser to maintain HTTPS after the policy takes effect.

- Network segmentation reduces exposure but does not encrypt the payload.

## 12. Retest

- **Positive:** the client correctly trusts CA/hostname and the application works through HTTPS.

- **Negative:** HTTP is blocked/safely redirected; wrong certificate or hostname causes client failure.

- **Boundary:** internal hop, proxy termination, redirect, client legacy, and metadata.

- **Telemetry:** compare the application marker with packet capture and TLS error.

## 13. Common Mistakes

- Call all HTTP public metadata sensitive findings.

- Disable certificate validation to 'use HTTPS'.

- Only encrypt client-to-proxy but leave proxy-to-origin in cleartext.

- Say HTTPS hides all IP, hostname, and traffic size.

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

- **Cleartext:** application data transmitted over the channel without an appropriate cryptographic security mechanism. [S5]

- **Authenticated TLS:** channel TLS has a verified certificate/hostname or peer identity. [S5]

- **Network metadata:** information such as peer IP and size/timing is not necessarily hidden by TLS. [S5]

## 16. Related Lessons and Further Reading

- [DNS Poisoning](../dns-poisoning/) — See more lessons about DNS Poisoning.

## 17. References

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — version/status: current version; accessed: 2026-07-17.
- **[S5]** RFC 8446 — The Transport Layer Security (TLS) Protocol Version 1.3. https://www.rfc-editor.org/rfc/rfc8446.html — version/date: August 2018; accessed: 2026-07-18.