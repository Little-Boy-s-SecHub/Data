---
schema_version: 1
id: WEB-A02-LAX-SECURITY-SETTINGS
title: "Lax Security Settings"
slug: lax-security-settings
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A02:2025
cwe:
  - CWE-614
  - CWE-1004
  - CWE-1275
content_status: technical-review
payload_status: none
last_verified: null
---

# Lax Security Settings

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain Lax Security Settings by root cause instead of just describing the consequences. 
- Identify trust boundary, asset, actor, and necessary conditions for the flaw to be exploitable. 
- Conduct controlled testing in a local lab and distinguish expected results from false positives. 
- Choose root controls, deploy fixes, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- Cookie scope/attributes and session lifecycle.

- Express 4.x, express-session and reverse-proxy trust.

- How browsers handle Secure, HttpOnly, and SameSite.

## 3. Background Knowledge

Imagine you hire a security company to protect your home. Upon handover, this company installs security cameras and door locks for you. However, they leave the camera's default password as `admin123`, only lock the front door while forgetting to lock the windows, and use easily copyable keys. These vulnerabilities are precisely an example of **lax security settings**. Thieves don't need to use sophisticated lock-picking tools; they just need to try the default password or climb through an open window to break into your house. [S3]

In the web environment, one of the most common configuration weaknesses lies in how applications manage **cookies** (pieces of information stored in the browser to maintain login state, similar to a building access card). To protect this card from being copied or stolen by attackers, developers need to configure three security "locks":
- **HttpOnly**: This lock prevents JavaScript code (such as malicious code XSS) from reading the cookie through the `document.cookie` attribute.
- **Secure**: This lock requires the browser to only send the cookie over connections encrypted with HTTPS. Even if you use unsecured public Wi-Fi, attackers cannot eavesdrop and steal this cookie.
- **SameSite**: This lock restricts certain cases of cross-site cookie sending. This is defense-in-depth and does not replace CSRF tokens or a custom header with an CORS allowlist appropriate to the threat model. [S1]

```javascript
// Express.js session configuration using express-session with secure cookie flags
const express = require('express');
const session = require('express-session');
const app = express();
const sessionSecret = process.env.SESSION_SECRET;

if (!sessionSecret || sessionSecret.length < 32) {
    throw new Error('SESSION_SECRET must be supplied by the deployment secret store');
}

app.use(session({
    name: 'session_id', // Avoid using default cookie names like connect.sid
    secret: sessionSecret, // Load the signing secret from the deployment secret store
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true, // Prevent client-side scripts from reading the cookie
        secure: true,   // Ensure the cookie is only transmitted over HTTPS
        sameSite: 'lax', // Defense in depth; state-changing routes still require CSRF protection
        maxAge: 3600000 // Session expires after 1 hour (value in milliseconds)
    }
}));
```

## 4. Description and Root Cause

The **Lax Security Settings** vulnerability occurs when developers or system administrators keep unsafe default settings, forget to enable important security flags, or open unnecessary network ports and services. [S3]

This vulnerability is extremely dangerous because it opens up the easiest paths for attackers. Simply by lacking security flags such as `HttpOnly` or `Secure` on cookies, an attacker can easily steal a user's session through XSS attacks or network eavesdropping. Additionally, exposing server version information, enabling directory listing, or not setting protective HTTP response headers (such as CSP, X-Frame-Options) will provide the attacker with the entire structural map of the application, making it easy for them to plan and carry out subsequent destructive attacks. [S3]


> **Mapping note:** metadata maps the cookie flags section in the lesson: missing `Secure` (CWE-614), missing `HttpOnly` on sensitive cookies (CWE-1004), and `SameSite` not matching the threat model (CWE-1275). These CWE do not represent all loose security configurations; if the lesson extends to headers, services, or other secrets, separate CWE must be attached with evidence. [S5], [S6], [S7]

## 5. Threat Model and Exploitation Conditions

- **Assets:** synthetic session cookie, response headers, and publicly available configuration information.

- **Actor:** browser user lab and script/control origin; do not use a real session.

- **Trust boundary:** Express.js session config, reverse proxy TLS and Apache/Nginx response headers.

- **Necessary condition:** a specific setting is missing/incorrect; impact depends on XSS, HTTP, or the corresponding cross-site request.

- **Environment:** Express 4.x, pinned version of express-session, pinned version of Chromium, and HTTPS loopback.

Do not group all headers into one vulnerability: each setting must have its own threat model, baseline, and evidence; SameSite is only defense-in-depth for CSRF. [S1]

## 6. Attack Mechanism

Each incorrect setting opens a separate path: missing HttpOnly allows scripts to read cookies, missing Secure for HTTP transport, or an inappropriate SameSite policy for cross-site flows. Impact can only be concluded according to the correct prerequisite of that setting. [S1]

## 7. Testing in an Authorized Lab

1. **Setup:** load SESSION_SECRET from the lab secret store, run the HTTPS fixture and pin Chromium.  
2. **Baseline:** verify that Set-Cookie has HttpOnly/Secure/SameSite according to the threat model and that headers do not expose the version.  
3. **Actions:** enable each misconfiguration on a separate snapshot; observe document.cookie, HTTP transport, or appropriate cross-site request.  
4. **Expected result:** the vulnerable version lacks the correct attribute; the fix sets the cookie securely but CSRF test still relies on token/custom header.  
5. **Boundary:** check reverse-proxy trust, localhost/HTTPS, cookie Domain/Path, and error responses.  
6. **Cleanup:** delete session/browser profile and secret fixture.

## 8. Payloads and Scope of Applicability

The blocks below are minimal lab examples according to the context recorded in the annotation. Before use, check the framework/version, encoding, expected result, and risk; only run in an authorized local fixture. Extended payload belongs to `security_cheatsheet.md`; lessons only retain the core examples.

Step 1: The web application sets a session cookie but does not assign security flags such as `HttpOnly` and `Secure`.
Step 2: The attacker injects a malicious script (through another vulnerability XSS) into the website that the victim is visiting.
Step 3: The malicious script runs on the victim's browser, reads the cookie through the `document.cookie` attribute (due to the missing `HttpOnly` flag), and sends it to the attacker's server.
Step 4: The attacker uses the obtained cookie to impersonate the victim's session on another browser. [S3]

## 9. Vulnerable Code and Secure Code

```javascript
// VULNERABLE Express 4.x configuration for the session fixture
app.set('trust proxy', true);
app.use(session({
    secret: 'development-secret',
    resave: false,
    saveUninitialized: true,
    cookie: { httpOnly: false, secure: false, sameSite: false },
}));
```

```javascript
// SECURE Express 4.x configuration for the same session use case
const sessionSecret = process.env.SESSION_SECRET;
if (!sessionSecret) {
    throw new Error('SESSION_SECRET must come from the deployment secret store');
}

// Trust only the known reverse-proxy hop used by this deployment.
app.set('trust proxy', 1);
app.use(session({
    name: '__Host-session_id',
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: true,
        sameSite: 'lax',
        path: '/',
        maxAge: 60 * 60 * 1000,
    },
}));
```
Cookie attributes must be set on the session-owning component instead of modifying the string `Set-Cookie` using regex at the reverse proxy. Prefix `__Host-` requires `Secure`, `Path=/`, and has no `Domain` attribute; `SameSite=Lax` is only defense-in-depth, and state-changing routes still need to control CSRF appropriately. [S3], [S4]

## 10. Detection

- Log in on Chromium and then check `Set-Cookie`, the cookie jar, and cross-site behavior. [S3]

- Review session secret, proxy trust, cookie name/path/domain and production configuration. [S3], [S4]

- Collect headers on both success/error; do not log session ID or secret.

## 11. Defense

### Compulsory control

- Configure a session secret strong enough outside the source and set cookies as Secure, HttpOnly, SameSite according to the threat model. [S3], [S4]

- Limit proxy trust and use HTTPS before enabling Secure cookie. [S4]

### Defense-in-depth

- Use the prefix `__Host-` when responding Secure, Path=/ and no Domain. [S3]

- Rotate/invalidate session according to the appropriate lifecycle.

## 12. Retest

- **Positive:** logging in HTTPS creates cookies with the correct attributes and active session.

- **Negative:** HTTP/cross-site context outside policy does not receive or send cookies.

- **Boundary:** proxy hop, subdomain, expiry, logout, and error response.

- **Telemetry:** check cookie jar and session-store events without exposing the token.

## 13. Common Mistakes

- Use regex on the proxy to fix all `Set-Cookie` without understanding the owner.

- Turn on `trust proxy` for all sources.

- Consider SameSite as the only CSRF measure.

- Record session ID or secret in the test log.

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

- **HttpOnly:** prevents JavaScript from reading cookies via API like `Document.cookie`. [S3]

- **Secure:** requires the browser to only send cookies over secure connections according to cookie semantics. [S3]

- **SameSite:** limits certain cases of sending cookies cross-site; does not replace the original CSRF control. [S3]

## 16. Related Lessons and Further Reading

- [Clickjacking](../clickjacking/) — See more lessons about Clickjacking.

## 17. References

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — version/status: current version; accessed: 2026-07-17.  
- **[S3]** MDN — Set-Cookie header. https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie — version/status: current version; accessed: 2026-07-18.  
- **[S4]** express-session documentation — cookie options and proxy deployment. https://expressjs.com/en/resources/middleware/session.html — version/status: current document; accessed: 2026-07-18.  
- **[S5]** CWE-614 — Sensitive Cookie in HTTPS Session Without 'Secure' Attribute. https://cwe.mitre.org/data/definitions/614.html — version/status: current version; accessed: 2026-07-18.  
- **[S6]** CWE-1004 — Sensitive Cookie Without 'HttpOnly' Flag. https://cwe.mitre.org/data/definitions/1004.html — version/status: current version; accessed: 2026-07-18.  
- **[S7]** CWE-1275 — Sensitive Cookie with Improper SameSite Attribute. https://cwe.mitre.org/data/definitions/1275.html — version/status: current version; accessed: 2026-07-18.