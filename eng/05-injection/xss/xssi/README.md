---
schema_version: 1
id: WEB-A05-XSS-XSSI
title: "Cross-Site Script Inclusion"
slug: xss-xssi
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A01:2025
cwe:
  - CWE-200
content_status: technical-review
payload_status: none
last_verified: null
---

# Cross-Site Script Inclusion

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain Cross-Site Script Inclusion by the root cause instead of just describing the consequences.
- Identify the trust boundary, asset, actor, and necessary conditions for the vulnerability to be exploitable.
- Conduct controlled testing in a local lab and differentiate between expected results and false positives.
- Choose the root control, implement the fix, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- Understand the HTTP request/response flow in Cross-Site Script Inclusion scenarios and how to apply input handling across trust boundaries. 
- Distinguish between authentication, authorization, and validation.
- Be able to read code/configuration in the language or framework appearing in the example.
- Have a local isolated lab, synthetic data, observable logs, and clear testing permissions.

## 3. Background Knowledge

The same-origin policy (SOP) restricts one origin from reading the response of another origin through multiple API. However, the script-loading mechanism allows the browser to send cross-origin requests and execute resources classified as JavaScript; this does not automatically allow the page to read the response bytes. XSSI only occurs when dynamic resources carrying sensitive data create observable side effects in a specific runtime. [S3] [S4]

### Example code functioning normally (Secure JSON Response with Anti-XSSI)```javascript
const express = require('express');
const app = express();

// Secure middleware setting HTTP headers to prevent MIME-sniffing
app.use((req, res, next) => {
    // Force browser to respect the declared Content-Type (prevents executing non-JS as JS)
    res.setHeader('X-Content-Type-Options', 'nosniff');
    next();
});

// Secure API endpoint returning user profile details
app.get('/api/user-profile', (req, res) => {
    const userProfile = {
        username: "johndoe",
        email: "johndoe@victim.lab.test",
        role: "user"
    };

    // Return content type as application/json rather than application/javascript
    res.setHeader('Content-Type', 'application/json');

    // Optional compatibility measure for clients that explicitly strip this prefix.
    // It is defense-in-depth for specific legacy JSON-hijacking patterns.
    const antiXssiPrefix = ")]}',\n";
    res.send(antiXssiPrefix + JSON.stringify(userProfile));
});
```

## 4. Description and Root Cause

XSSI occurs when another origin can load dynamic JavaScript resources containing sensitive data and that data becomes observable via side effects, global variables, callbacks, or techniques suitable for the browser/runtime. The script loading element can send cross-origin requests, but the ability to read data does not automatically follow just from a successful request. Cookies also depend on `SameSite` and the request context; it is necessary to demonstrate that the data is observable in the browser fixture. [S3] [S4]

> **Reference:** technical claims in the lesson are marked with source markers; when applying in practice, refer to the version/framework being used: [S1], [S2].

## 5. Threat Model and Exploitation Conditions

- **Assets:** dynamic profile and session cookie API. 
- **Actor, authentication, and role:** untrusted origin includes resource when user role has aggregated session. 
- **Exploitation conditions:** sensitive data is returned under JavaScript observable cross-origin or JSON legacy weak. 
- **Browser, proxy, framework, and version:** Chromium and Express 4.x pinned on victim/untrusted .lab.test; record SameSite status; must save actual image/package version along with evidence. 
- **Mandatory evidence:** together with correlation ID must link input, control decision, and impact the correct asset; individual status code is not enough. [S1]

## 6. Attack Mechanism

For xssi, sensitive data is returned under JavaScript observable cross-origin or JSON legacy weak. The positive case must prove that the input reaches the correct sink and creates the described impact; the negative case, when origin control is enabled, must be blocked before side effects. The conclusion only applies to the environment pinned in section 5. [S1]

## 7. Testing in an Authorized Lab

1. **Setup:** launch Chromium and Express 4.x pinned on victim/untrusted .lab.test; record the SameSite status; only load synthetic data, enable application/proxy/datastore logging, and attach correlation ID. 
2. **Baseline:** send a valid input of the XSSI use case; save raw request/response, decide policy and asset status before testing. 
3. **Input and actions:** use exactly one core payload in item 8 in the annotated context; change one variable at a time and comply with the request cap. 
4. **Expected result:** consider the vulnerable fixture as positive only when the log proves the mechanism of “sensitive data returned under JavaScript observable cross-origin or JSON legacy weak”; secure fixture must block before side effect and boundary input must fail closed. 
5. **Cleanup:** delete XSSI data, markers, and logs; revoke related session/cache, restore snapshot, and confirm no remaining callback/test process. 
6. **Safety limits:** run only on loopback/`.lab.test`; do not use real targets, credentials, or data; OOB/DoS/state-changing must comply with network/CPU/memory/request cap.

## 8. Payloads and Scope of Applicability

The blocks below are minimal lab examples according to the context recorded in the annotation. Before use, check the framework/version, encoding, expected result, and risk; only run in an authorized local fixture. Extended payload belongs to `security_cheatsheet.md`; lessons only retain the core examples.

In the lab, page `untrusted.lab.test` loads `https://victim.lab.test/js/user-profile.js`. A vulnerability is only recorded if the browser trace shows that the cookie is actually sent according to the `SameSite` configuration of the fixture and the script produces a value/side effect that the origin does not trustedly observe; simply successfully loading the resource is not enough.

## 9. Vulnerable Code and Secure Code

The following two endpoints use Express 4.x for the same use case of returning authenticated profiles. Dynamic JavaScript responses that create global side effects are a design prone to XSSI; JSON does not execute and `nosniff` reduces this surface. The prefix is only defense-in-depth for legacy clients, not a substitute for content type and authorization. [S2] [S3] [S4]

### Not safe (vulnerable): returns sensitive data in the form of dynamic JavaScript

```javascript
app.get('/api/user-profile.js', requireSession, (req, res) => {
    const profile = { name: req.user.name, email: req.user.email };
    // Vulnerable: cross-origin script loading can observe this global side effect
    res.type('application/javascript');
    res.send(`window.profile = ${JSON.stringify(profile)};`);
});
```
### Secure: return JSON does not execute

```javascript
app.use((req, res, next) => {
    // Prevent browsers from MIME-sniffing the response as script
    res.setHeader('X-Content-Type-Options', 'nosniff');
    next();
});

app.get('/api/user-profile', requireSession, (req, res) => {
    const profile = { name: req.user.name, email: req.user.email };

    // Optional legacy defense for clients that explicitly strip this prefix
    res.type('application/json');
    res.send(")]}',\n" + JSON.stringify(profile));
});
```

## 10. Detection

- Log the actor/session, route or operation, object/resource related to Cross-Site Script Inclusion, the policy result, and correlation ID; do not log secrets or entire tokens.  
- Compare authorization/validation failures with a valid baseline and alert based on behavior chains, not just a single payload chain.  
- Combine application, reverse proxy, and datastore telemetry to confirm whether the request reached the sink and whether there was any impact.  
- Scanner or WAF alerts are only investigation signals; they are not the sole proof that a vulnerability exists. [S1]

## 11. Defense

### Compulsory control

- Return authentication data with JSON correctly MIME/nosniff, not by executable JavaScript. 
- Apply the same control to all routes, operations, and equivalent processing paths; failures must stop before any side effects.

### Defense-in-depth

With Cross-Site Script Inclusion, the measures below help reduce the blast radius or increase detection capability. Rate limit, UUID unpredictable, WAF, CSP, or general validation should not be used as a substitute for original controls.

- **Summary**: Do not expose sensitive data in JavaScript that can be included cross-origin; require proper authentication/authorization, using JSON with `application/json` and `nosniff`. The Anti-XSSI prefix is only a defense-in-depth measure for the client and compatible attack types.  
- **Detailed steps**:  
  - Absolutely do not embed sensitive information or users' personal data as variables in static or dynamic JavaScript files.  
  - Use the JSON data format to transmit information, and validate API requests using anti-CSRF tokens or Authorization headers instead of relying solely on session cookies.  
  - A prefix like `)]}',\n` may be used if all clients proactively remove it and browser regression testing confirms effectiveness; do not treat this prefix as a universal control for all forms of XSSI.  
  - Set the `X-Content-Type-Options: nosniff` response header to force browsers not to execute non-script format files (such as JSON, CSV) as scripts.  
  - Configure the CORS policy to limit valid access sources to sensitive endpoints.

## 12. Retest

- **Positive case:** with Cross-Site Script Inclusion, valid flows still work correctly for permitted actors and data.  
- **Negative case:** same input/resource but unauthorized actor or context is denied without leaking sensitive details.  
- **Boundary case:** test empty values, edge extremes, different encodings, repeated requests, expired session state, and equivalent paths/operations.  
- **Telemetry:** confirm policy decisions, application logs, proxy logs, and datastore side effects match correlation ID.  
- **Retest:** save a minimal scenario reproducing the old error and demonstrate the fix does not depend on WAF/rate limit.

## 13. Common Mistakes

- Only check the status code or response string of Cross-Site Script Inclusion without verifying side effects and logs.  
- Use a payload with correct syntax but wrong DBMS, browser, framework, protocol, or injection context.  
- Treat UUID, rate limit, WAF, CSP, or general input validation as a fix for a different root control.  
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
- [ ] Cleanup completed; no secrets, real targets, Internet callbacks, or customer data remain.

## 15. Glossary

- **XSSI (Cross-Site Script Inclusion)**: A vulnerability that allows a malicious website to read sensitive data embedded in another website's dynamic JavaScript files.
- **SOP (Same-Origin Policy)**: A security mechanism that blocks cross-origin access to resources.
- **Dynamic JavaScript**: JavaScript files dynamically generated according to the specific context of each user session.
- **MIME Sniffing**: A feature that automatically identifies the actual file format of the browser regardless of the header declaration.
- **Nosniff**: A configuration value of the X-Content-Type-Options header that prevents MIME sniffing by the browser.

## 16. Related Lessons and Further Reading

- [Reflected XSS](../reflected/) — Script reflection vulnerability.

## 17. References

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — version/status: current version; accessed: 2026-07-17.
- **[S2]** CWE-200. https://cwe.mitre.org/data/definitions/200.html — version/status: current version; accessed: 2026-07-17.
- **[S3]** WHATWG HTML Living Standard — The script element. https://html.spec.whatwg.org/multipage/scripting.html#the-script-element — version/status: Living Standard; accessed: 2026-07-18.
- **[S4]** Fetch Living Standard — X-Content-Type-Options. https://fetch.spec.whatwg.org/#x-content-type-options-header — version/status: Living Standard; accessed: 2026-07-18.