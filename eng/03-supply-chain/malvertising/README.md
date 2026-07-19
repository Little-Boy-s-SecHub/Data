---
schema_version: 1
id: WEB-A03-MALVERTISING
title: "Malvertising"
slug: malvertising
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A08:2025
cwe:
  - CWE-829
content_status: technical-review
payload_status: none
last_verified: null
---

# Malvertising

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain Malvertising by root cause instead of just describing the consequences.
- Identify trust boundaries, assets, actors, and the necessary conditions for the vulnerability to be exploited.
- Perform controlled testing in a local lab and distinguish expected results from false positives.
- Select the root control, implement the fix, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- Third-party script execution and iframe sandbox.

- CSP, SRI and the limits of dynamic advertising resources.

- Browser fixture with ad origin and publisher origin separated.

## 3. Background Knowledge

Imagine you own a large and reputable online newspaper. To generate additional revenue to sustain operations, you sign a contract with a third-party advertising agency, allowing them to display a dynamic electronic billboard in a corner of the newspaper page. This agency will automatically change the advertisement content every few seconds (called **ad network architecture**). The content displayed on that billboard is loaded directly from the agency's server, and your newsroom has no control over or prior approval of each image or video uploaded.

One day, a malicious actor hacked into the server of that advertising agency, or disguised themselves as a customer buying legitimate ads. Instead of uploading a normal product introduction image, they secretly inserted a piece of malicious JavaScript code (called **third-party script embedding**). When readers visit your news site, their browsers automatically fetch this malicious code from the ad banner and execute it immediately. Because the code runs directly in the user's browser under the guise of your reputable news site, it can quietly steal session cookies, automatically download malware onto the user's device, or suddenly redirect them to a phishing website. [S4]

In typical integration, the publisher should isolate advertising content into a frame with minimal sandbox and not grant high-level navigation or access to the publisher's origin. If it is necessary to load an immutable script resource, the publisher can pin the exact bytes using Subresource Integrity and configure a compatible CORS; SRI is not suitable for advertising content that changes per request. The configuration pair in section 9 illustrates the same use case without setting experimental input outside of section 8. [S3]

## 4. Description and Root Cause

The **Malvertising** vulnerability occurs when a trusted website integrates code snippets or advertisement frames from third parties without applying the necessary isolation protection measures. [S4]

The danger of Malvertising lies in the fact that it breaks the integrity of a web application through a completely legitimate channel. Website owners often place absolute trust in major advertising networks, while these networks distribute highly dynamic and hard-to-control content. If mechanisms such as the `sandbox` attribute for ad-containing iframes are not used, or a strict content security policy (CSP) to limit script sources is lacking, your website will inadvertently become a launching pad for attackers to spread malware to millions of their trusted customers. [S4]


## 5. Threat Model and Exploitation Conditions

- **Assets:** DOM/publisher lab session and ad frame navigation rights.

- **Actor:** unreliable advertising content from ads.lab.test; user uses Chromium pin version.

- **Trust boundary:** iframe sandbox, CSP and script SRI when the publisher loads third-party resources.

- **Necessary condition:** ad/script is modified and lacks proper isolation/integrity; dynamic ad cannot automatically use SRI.

- **Environment:** publisher/ads origin loopback, fixture script has bytes and fixed SHA-384, does not load malware.

With cross-origin resources, SRI needs the response to be shared via CORS; `crossorigin="anonymous"` on the element does not itself make the server return ACAO. SRI blocks bytes different from the pinned hash, but does not protect when an attacker can modify both the resource **and** HTML/build containing the hash, and is not suitable for ad payloads that change per request. [S3]

Only use DOM marker/blocked navigation as evidence; do not release malicious ads or download executable files. [S1]

## 6. Attack Mechanism

The publisher loads a frame or script from the ad origin. If dynamic content has privileges exceeding the requirements and lacks a proper sandbox/CSP/integrity, changes in the ad supply chain are executed in a capability broader than expected. [S1]

## 7. Testing in an Authorized Lab

1. **Setup:** run the publisher and ads.lab.test loopback, pin Chromium, serve analytics-v1.js with the correct recorded bytes.
2. **Baseline:** sandboxed iframe operates with minimal privileges; pinned script has the correct hash and mock ad origin returns ACAO to the publisher.
3. **Actions:** change one byte of the script to check SRI; try top navigation from the synthetic frame when sandbox is missing/present.
4. **Expected result:** browser blocks incorrect digest and sandbox blocks behavior beyond privileges; misconfiguration only creates harmless marker.
5. **Boundary:** test CSP frame-src/script-src, ACAO missing/incorrect, redirect resource, hash in publisher changed and version modification.
6. **Cleanup:** clear cache/profile and stop origins.

## 8. Payloads and Scope of Applicability

The blocks below are minimal lab examples according to the context recorded in the annotation. Before use, check the framework/version, encoding, expected result, and risk; only run in an authorized local fixture. Extended payload belongs to `security_cheatsheet.md`; lessons only retain the core examples.

Step 1: The attacker purchases an advertising spot on an intermediary ad network. 
Step 2: The attacker inserts malicious JavaScript code into the ad content instead of the usual image. 
Step 3: The trusted website integrates the ad network's script to display ads to users. 
Step 4: When users visit the website, their browser loads the malicious ad and automatically executes the malicious script, redirecting users to a phishing site or downloading malware that the legitimate website is completely unaware of. [S4]

## 9. Vulnerable Code and Secure Code

```html
<!-- VULNERABLE: dynamic ad script executes with the publisher's DOM authority -->
<script src="https://ads.lab.test/dynamic-ad.js"></script>
```

```html
<!-- SECURE: the same dynamic ad is isolated in a minimally privileged frame -->
<iframe
  src="https://ads.lab.test/render/ad-42"
  sandbox="allow-scripts"
  referrerpolicy="no-referrer"
  title="Sponsored ad">
</iframe>
```
Publisher must also limit `frame-src` to the ad origin and only add the sandbox token that is really needed. Do not add `allow-same-origin`, `allow-top-navigation`, or `allow-popups-to-escape-sandbox` out of habit because those tokens return capabilities. For immutable scripts, use `integrity`/`crossorigin` and CORS appropriately; dynamic ads cannot be pinned to stable bytes, so they must be kept in an isolated frame. [S3], [S4]

## 10. Detection

- Load creative synthetic and verify the DOM/network rights of the actual script or iframe. [S4]

- Review how to embed ads, sandbox tokens, and which resources can be changed without changing URL. [S4]

- Collect frame tree, CSP violation and request origin; do not call the real ad network.

## 11. Defense

### Compulsory control

- Isolate untrusted creative in a sandboxed iframe with a minimal set of tokens according to functionality. [S4]

- Do not directly embed advertising scripts with same-origin privileges without proper trust/provenance. [S4]

### Defense-in-depth

- CSP limits the publisher's network/script according to the use case.

- SRI is only suitable for immutable resources with a pinned digest.

## 12. Retest

- **Positive:** The creative is valid, displayed in the sandbox, and does not require excessive permissions.

- **Negative:** creative synthetic does not modify DOM publisher or top-level navigation.

- **Boundary:** nested frame, popup, form, redirect, and creative update.

- **Telemetry:** cross-check frame permissions with network/DOM marker.

## 13. Common Mistakes

- Only rely on CSP when directly embedding third-party scripts.

- Add `allow-scripts` and `allow-same-origin` without evaluating the origin.

- Use SRI for URL with continuously changing content.

- Conclude malware delivery when only seeing ad requests.

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

- **Third-party script:** external script running in the context of the document when directly embedded. [S4]

- **Iframe sandbox:** limits the capabilities of content within the frame; the token only grants the necessary permissions. [S4]

- **SRI:** the browser checks the digest of the immutable sub-resource before use. [S3]

## 16. Related Lessons and Further Reading

- [Subdomain Squatting](../subdomain-squatting/) — See more lessons about Subdomain Squatting.

## 17. References

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — version/status: current version; accessed: 2026-07-17.
- **[S3]** W3C — Subresource Integrity. https://www.w3.org/TR/SRI/ — version/status: current specification; accessed: 2026-07-17.
- **[S4]** WHATWG HTML Standard — iframe sandbox. https://html.spec.whatwg.org/multipage/iframe-embed-object.html#attr-iframe-sandbox — version/status: Living Standard; accessed: 2026-07-18.