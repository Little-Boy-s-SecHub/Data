---
schema_version: 1
id: WEB-A02-CORS
title: "Cross-Origin Resource Sharing"
slug: cors
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A02:2025
cwe:
  - CWE-942
content_status: technical-review
payload_status: none
last_verified: null
---

# Cross-Origin Resource Sharing

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain Cross-Origin Resource Sharing by root cause rather than just describing the consequences. 
- Identify trust boundaries, assets, actors, and the necessary conditions for the vulnerability to be exploited. 
- Conduct controlled testing in a local lab and distinguish expected results from false positives. 
- Choose root controls, implement fixes, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- Origin tuple, Same-Origin Policy and Fetch/CORS.

- Safelisted request, preflight, and credential mode.

- Cache behavior with fields `Origin` and `Vary`.

## 3. Background Knowledge

Imagine you are living in a high-end apartment complex. The building management has an extremely strict security regulation: "Strangers outside are not allowed to enter residents' apartments to rummage through belongings or read letters." This basic safety rule in the browser world is called **SOP** (Same-Origin Policy). It ensures that a malicious script running on the entertainment website `callback.lab.test` cannot arbitrarily read your Facebook messages or bank account data that are open in a neighboring tab. An "origin" here is strictly defined by the combination of: protocol (http/https), domain name, and port. [S3]

However, in practice, modern web applications need to cooperate with each other. For example, a sales website (`shop.com`) needs to call API at `api.shop.com`. CORS specifies when a script from one origin can read the response of another origin. Browsers only send a preflight `OPTIONS` for requests that are not in the CORS-safelisted group, such as unsafelisted method/header; a “simple request” can be sent immediately, and CORS does not replace CSRF protection. [S3]

```javascript
// Express.js middleware for safe CORS policy handling
const express = require('express');
const app = express();

// Whitelist of trusted origins allowed to access the API
const allowedOrigins = ['https://www.victim.lab.test', 'https://api.victim.lab.test'];

app.use((req, res, next) => {
    const origin = req.headers.origin;

    const isAllowed = allowedOrigins.includes(origin);
    if (origin && !isAllowed) {
        return res.status(403).json({ error: 'Origin is not allowed' });
    }

    if (isAllowed) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.append('Vary', 'Origin');
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
        res.setHeader('Access-Control-Allow-Credentials', 'true');
    }

    // Answer only an allowed cross-origin preflight request here
    if (req.method === 'OPTIONS' && isAllowed) {
        return res.sendStatus(204);
    }

    next();
});
```

## 4. Description and Root Cause

The CORS vulnerability (CORS Misconfiguration) occurs when the gatekeeper (CORS configuration on API server) is too lax, lazy, or sets up the procedure incorrectly. [S3]

The most common mistake is arbitrarily reflecting `Origin` and simultaneously returning `Access-Control-Allow-Credentials: true`. To read data using cookies, the script must also send requests with credentials mode, and the cookie must be allowed to be attached to the request according to `SameSite`, `Secure`, domain/path, and site context. ACAC does not automatically make the browser send cookies; it is a condition for the browser to allow the script to read a credentialed response. CORS also does not replace CSRF protection for requests that have side effects. [S3]


## 5. Threat Model and Exploitation Conditions

- **Assets:** API synthetic response is protected by cookie/session.

- **Actor:** script on attacker.lab.test in Chromium; the victim has logged into the lab if checking credentialed CORS.

- **Trust boundary:** middleware CORS Express.js 4.x creates Access-Control-Allow-* based on Origin.

- **Necessary conditions:** the origin is not trusted to be allowed and the browser allows the script to read the response; CSRF is a specific threat.

- **Environment:** attacker/api origin loopback, Chromium pin version, preflight/network log enabled.

The request being sent does not mean CORS is bypassed; it must be proven that JavaScript can read sensitive responses according to SOP/CORS. [S1]

## 6. Attack Mechanism

Browser sends `Origin`; when the script requests a credentialed fetch and the cookie policy allows attaching cookies, middleware returning ACAO/ACAC incorrectly may allow a JavaScript attacker to read the response. If the cookie is not sent, the endpoint does not use other credentials, or the response does not contain sensitive data, with the same header configuration this impact is not proven. [S1], [S3]

## 7. Testing in an Authorized Lab

1. **Setup:** run attacker and API Express loopback, pin Chromium, seed session/data synthetic.
2. **Baseline:** origin allowlist reads response; attacker origin is blocked.
3. **Action:** from attacker origin send simple and preflight requests, with/without credentials depending on the case.
4. **Expected result:** error for script reading marker; fix does not provide wrong ACAO/ACAC and browser blocks reading.
5. **Boundary:** test null Origin, subdomain suffix, different port, and cache Vary: Origin.
6. **Cleanup:** delete cookies/profile and stop fixture.

## 8. Payloads and Scope of Applicability

The blocks below are minimal lab examples according to the context recorded in the annotation. Before use, check the framework/version, encoding, expected result, and risk; only run in an authorized local fixture. Extended payload belongs to `security_cheatsheet.md`; lessons only retain the core examples.

The developer temporarily reflected origin CORS for debugging and then deployed it by mistake. In the fixture, the user was logged in, the cookie was configured to allow credentialed cross-site requests, and the attacker script used `credentials: 'include'`. If API also reflects the attacker's origin and returns ACAC, the browser allows the script to read the synthetic balance marker. Cookie attachment and response readability must be checked separately; they should not be inferred only from header CORS. [S3]

## 9. Vulnerable Code and Secure Code

```javascript
// Express.js safe CORS middleware using CORS module with strict whitelist
const express = require('express');
const cors = require('cors');
const app = express();

// === VULNERABLE CODE: reflects every Origin while allowing credentials ===
app.use('/vulnerable-api', cors({
  origin: true,
  credentials: true
}));

// === SECURE CODE (same Express.js/CORS use case) ===
const allowedOrigins = ['https://trusted.victim.lab.test', 'https://admin.victim.lab.test'];

const corsOptions = {
  origin: function (origin, callback) {
    // Requests without Origin are outside browser CORS; route auth still applies
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(null, false);
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
};

app.use('/api', cors(corsOptions));
```

## 10. Detection

- Run requests from allowed and disallowed origins; check if the browser allows the script to read the response. [S3]

- Review reflection logic `Origin`, credentials, preflight, and `Vary: Origin`. [S3]

- Capture CORS request/response along with the browser console; differentiate between the sent request and the read response.

## 11. Defense

### Compulsory control

- The origin match has been parsed with the correct allowlist; only send ACAO to the allowed origin. [S3]

- Only enable credentials when necessary and do not combine them with a wildcard origin. [S3]

### Defense-in-depth

- Keep authorization/CSRF control independent from CORS.

- Cache response according to `Origin` when the header content changes.

## 12. Retest

- **Positive:** origin allowlisted can correctly read the required response.

- **Negative:** origins outside the allowlist cannot read credentialed responses.

- **Boundary:** `null` origin, different port, similar subdomain, preflight, and cache.

- **Telemetry:** saving Origin, ACAO/ACAC, credential mode and policy decision.

## 13. Common Mistakes

- Reflect all values `Origin`.

- Use substring or suffix without checking label boundary.

- Regard preflight as an authorization mechanism.

- Only check whether the request is sent, do not check the browser for reading the response.

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

- **Origin:** tuple scheme, host and port used in same-origin checks. [S3]

- **CORS:** the header protocol allows the server to relax some cross-origin read permissions of the browser. [S3]

- **Preflight:** request `OPTIONS` that the browser sends before some requests that are not safelisted. [S3]

## 16. Related Lessons and Further Reading

- [Clickjacking](../clickjacking/) — See more lessons about Clickjacking.

## 17. References

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — version/status: current version; accessed: 2026-07-17.
- **[S3]** WHATWG Fetch Standard — CORS protocol and preflight fetch. https://fetch.spec.whatwg.org/ — version/status: Living Standard; accessed: 2026-07-17.