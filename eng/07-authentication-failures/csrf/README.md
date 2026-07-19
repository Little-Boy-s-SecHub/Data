---
schema_version: 1
id: WEB-A07-CSRF
title: "Cross-Site Request Forgery"
slug: csrf
level: beginner
estimated_minutes: 35
prerequisites:
  - http-fundamentals
  - authorized-security-testing
  - authentication-vs-authorization
owasp:
  - A01:2025
cwe:
  - CWE-352
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Cross-Site Request Forgery

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain Cross-Site Request Forgery by root cause instead of just describing the consequences.
- Identify trust boundaries, assets, actors, and the necessary conditions for the vulnerability to be exploited.
- Conduct controlled testing in a local lab and differentiate expected results from false positives.
- Select root controls, implement fixes, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- Understand the HTTP request/response flow of Cross-Site Request Forgery scenarios and how to apply input handling across trust boundaries. 
- Distinguish between authentication, authorization, and validation. 
- Be able to read code/configuration in the language or framework shown in the example. 
- Have a local lab isolated, synthetic data, observable logs, and clear testing permissions.

## 3. Background Knowledge

Imagine you are logging into your bank account on a browser to transfer money. After completing the transaction, you do not log out but open a new tab to read entertainment news. By accident, you click on a sensational lesson that leads to a strange, malicious website.

This malicious website immediately runs a hidden piece of code to send a money transfer request from your account to the attacker's account. Because you are still logged into the banking site, your browser will, by default habit, automatically attach your session cookie to that request and send it. The bank receives the request with your valid key, so it immediately transfers the money without knowing that the request was sent from the adjacent malicious tab. This is exactly a **Cross-Site Request Forgery (CSRF)** attack.

To prevent this type of fraud, systems use two layers of protective shields:
1. **SameSite Cookie**: This attribute restricts certain cases where browsers send cookies in a cross-site context. Behavior differs between `Strict`, `Lax`, and `None`, and also depends on the type of navigation/request; this is defense-in-depth and does not replace tokens in every threat model. [S3]
2. **Anti-CSRF Token**: The server issues a secret value tied to the session or request and verifies it on state-changing operations. The token does not have to be used once per form; the core requirement is that a cross-site attacker cannot guess/read it and the server validates it correctly. [S3]

```javascript
const express = require('express');
const cookieParser = require('cookie-parser');
const { doubleCsrf } = require('csrf-csrf');
const app = express();

const csrfSecret = process.env.CSRF_SECRET;
if (!csrfSecret || Buffer.byteLength(csrfSecret, 'utf8') < 32) {
    throw new Error('CSRF_SECRET must contain at least 32 UTF-8 bytes');
}

app.use(express.json());
app.use(cookieParser(csrfSecret));

// Initialize doubleCsrf helper configuration
const {
    generateToken,
    doubleCsrfProtection
} = doubleCsrf({
    getSecret: () => csrfSecret,
    cookieName: "x-csrf-token",
    cookieOptions: {
        sameSite: "lax", // Protects cookies from being sent in cross-site requests
        path: "/",
        secure: true,    // Requires HTTPS execution environment
        httpOnly: true   // Protects against client-side script access
    },
});

// Route to fetch CSRF token for the frontend form
app.get('/api/csrf-token', (req, res) => {
    const token = generateToken(req, res);
    res.json({ csrfToken: token });
});

// Secure API endpoint protected by CSRF verification middleware
app.post('/api/transfer-funds', doubleCsrfProtection, (req, res) => {
    // Process secure database transaction after successful verification
    res.json({ message: "Transaction completed successfully" });
});
```

## 4. Description and Root Cause

The CSRF vulnerability (Cross-Site Request Forgery) occurs when a web application blindly trusts requests sent by the browser based solely on whether an authentication cookie is attached.

The danger of this vulnerability lies in the fact that an attacker can exploit the victim's active login session to carry out destructive actions without their knowledge, such as automatically changing the account password, altering the linked email, or executing unauthorized money transfer transactions simply by tricking the victim into visiting a malicious link they have prepared.

> **Reference source:** technical claims in the lesson are tagged with source markers; when applying in practice, compare with the version/framework being used: [S1], [S2], [S3].

## 5. Threat Model and Exploitation Conditions

- **Assets:** email change/transfer operation and session cookie. 
- **Actor, authentication and role:** untrusted origin causing a logged-in user's browser to send requests. 
- **Exploitation conditions:** server trusts ambient cookie but lacks CSRF token or custom header with origin. 
- **Browser, proxy, framework and version:** Chromium and Express 4.x csrf-csrf pinned on .lab.test; SameSite state recorded; must save actual image/package version along with evidence. 
- **Mandatory evidence:** must link input with correlation ID, determine control and impact on the correct asset; individual status codes are not sufficient. [S1]

## 6. Attack Mechanism

Regarding CSRF, the server trusts ambient cookies but lacks an CSRF token or a custom header attached to the origin. The positive case must prove that the input reaches the correct sink and produces the described effect; the negative case should be blocked before the side effect when origin control is enabled. The conclusion only applies to the environment pinned in item 5. [S1]

## 7. Testing in an Authorized Lab

1. **Setup:** launch Chromium and Express 4.x csrf-csrf pinned on .lab.test; record SameSite status; only load synthetic data, enable application/proxy/datastore logs, and attach correlation ID.
2. **Baseline:** send a valid input of the csrf use case; save raw request/response, decide policy and asset status before the test.
3. **Input and actions:** use exactly one core payload in item 8 within the annotated context; change one variable at a time and comply with request cap.
4. **Expected result:** only consider a vulnerable fixture as positive when the log proves the mechanism “server trusts ambient cookie but lacks CSRF token or origin-attached custom header”; secure fixture must block side effects and boundary input must fail closed.
5. **Cleanup:** delete csrf data, markers, and logs; revoke related session/cache, restore snapshot, and confirm no remaining test callbacks/processes.
6. **Safety limits:** only run on loopback/`.lab.test`; do not use a target, real credentials, or real data; OOB/DoS/state-changing must have network/CPU/memory/request cap.

## 8. Payloads and Scope of Applicability

The blocks below are minimal lab examples according to the context recorded in the annotation. Before use, check the framework/version, encoding, expected result, and risk; only run in an authorized local fixture. Extended payload belongs to `security_cheatsheet.md`; lessons only retain the core examples.

The attacker noticed that an application allows creating written lessons using simple GET requests. He sent the victim a link pointing to URL to post a written lesson with a custom payload. When the victim clicks the link while logged in, the browser automatically transmits the authentication cookies, creating a spam-posted lesson that acts as a computer worm.

### JSON CSRF via Content-Type
Many frameworks protect CSRF by checking the Content-Type. However, if the endpoint accepts both `text/plain` and parses the content like JSON:

<!-- payload-id: WEB-A07-CSRF-001 -->
<!-- context: pinned Chromium submits a text/plain form cross-site to the Express fixture -->
<!-- prerequisites: Chromium fixture; synthetic account; endpoint intentionally accepts text/plain as JSON -->
<!-- encoding: UTF-8 HTML; browser serializes the crafted input as a text/plain form body and preserves the embedded JSON punctuation -->
<!-- expected-result: synthetic account email changes once and audit log records the cross-site request -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```html
<!-- Malicious page: sends JSON data via form with text/plain enctype -->
<form action="https://victim.lab.test/api/update-email" method="POST"
      enctype="text/plain">
  <!-- text/plain is CORS-safelisted, so this form submission is not preflighted -->
  <input name='{"email":"fixture@untrusted.lab.test", "_dummy":"' value='"}'>
</form>
<script>document.forms[0].submit();</script>
```
This is not a “bypass CORS”: forms create a simple request that the browser is allowed to send, while SOP/CORS can still prevent the attacking page from reading the response. With JSON-only API, rejecting simple content types helps narrow the surface; origin control is still an CSRF token or a custom header accompanied by a strict CORS allowlist, and `SameSite` is defense-in-depth according to the threat model. [S3]

## 9. Vulnerable Code and Secure Code

The following two handlers use Express 4.x and `csrf-csrf` 4.x for the same endpoint to change the status. Session cookies are automatically sent by the browser, so if the route only checks the session without verifying the user's intentional request, it is prone to CSRF. The token checked by the middleware is the root control in the example; `SameSite` is an additional layer and must fit the use case. [S3] [S4]

### Not secure (vulnerable): only check session

```javascript
app.post('/transfer', requireSession, (req, res) => {
  // Vulnerable: a valid session cookie is not proof of request intent
  transferStore.apply(req.user.id, req.body.recipient, req.body.amount);
  res.send('Transfer processed');
});
```
### Secure: verify CSRF token before side effect

```javascript
const express = require('express');
const cookieParser = require('cookie-parser');
const { doubleCsrf } = require('csrf-csrf');

const app = express();

const csrfSecret = process.env.CSRF_SECRET;
if (!csrfSecret || Buffer.byteLength(csrfSecret, 'utf8') < 32) {
  throw new Error('CSRF_SECRET must contain at least 32 UTF-8 bytes');
}

app.use(express.urlencoded({ extended: false }));
// sessionMiddleware is configured before cookie-parser as required by the package
app.use(sessionMiddleware);
app.use(cookieParser());

const {
  generateCsrfToken,
  doubleCsrfProtection
} = doubleCsrf({
  getSecret: () => csrfSecret,
  getSessionIdentifier: (req) => req.session.id,
  cookieName: "__Host-psifi.x-csrf-token",
  cookieOptions: {
    sameSite: "strict",
    path: "/",
    secure: true,
  },
  // This server-rendered form sends the token in one explicit body field
  getCsrfTokenFromRequest: (req) => req.body._csrf,
});

app.get('/transfer-form', requireSession, (req, res) => {
  const csrfToken = generateCsrfToken(req, res);
  res.render('transfer', { csrfToken });
});

app.post('/transfer', requireSession, doubleCsrfProtection, (req, res) => {
  // Secure: token validation completes before the state-changing operation
  transferStore.apply(req.user.id, req.body.recipient, req.body.amount);
  res.send('Transfer processed');
});
```

## 10. Detection

- Log the actor/session, route or operation, object/resource related to Cross-Site Request Forgery, policy results and correlation ID; do not log secrets or entire tokens.  
- Compare authorization/validation failures with a valid baseline and alert based on behavior chains, not just a single payload chain.  
- Combine application telemetry, reverse proxy, and datastore to confirm whether the request reached the sink and whether there was any impact.  
- Scanner or WAF alerts are only investigation signals; they are not the sole proof that a vulnerability exists. [S1]

## 11. Defense

### Compulsory control

- Verify the CSRF token attached to the session or custom header with strict CORS on all state-changing routes.
- Apply the same control to all routes, operations, and equivalent handling paths; failure must stop before side effects.

### Defense-in-depth

With Cross-Site Request Forgery, the measures below help reduce the blast radius or increase detection capability. Rate limit, UUID unpredictable, WAF, CSP, or general validation should not be used to replace original controls.

- **Summary**: Use unique and cryptographically secure anti-CSRF tokens, apply the SameSite cookie attribute, and restrict state-changing actions to POST/PUT/DELETE methods.  
- **Detailed steps**:  
  - Implement unique and cryptographically secure anti-CSRF tokens for all state-changing activities.  
  - Choose `SameSite=Lax` or `Strict` according to the login/navigation flow and test on supported browsers; do not consider SameSite as a control for unique CSRF.  
  - Ensure all state-changing actions require HTTP methods such as POST, PUT, or DELETE, instead of GET.  
  - Use modern, maintained libraries (such as csrf-csrf for the Double Submit Cookie pattern) to manage and validate anti-CSRF tokens.

## 12. Retest

- **Positive case:** with Cross-Site Request Forgery, a valid flow still works correctly for the actor and allowed data. 
- **Negative case:** for the same input/resource but an unauthorized actor or context, it is denied without leaking sensitive details. 
- **Boundary case:** test empty values, extremes, different encoding, repeated requests, expired session states, and equivalent paths/operations. 
- **Telemetry:** confirm policy decisions, application logs, proxy logs, and datastore side effects match correlation ID. 
- **Re-test:** save a minimal scenario that reproduces the old bug and proves the fix does not depend on WAF/rate limit.

## 13. Common Mistakes

- Only check the status code or response string of Cross-Site Request Forgery without verifying side effects and logs.  
- Use a syntactically correct payload but with the wrong DBMS, browser, framework, protocol, or injection context.  
- Consider UUID, rate limit, WAF, CSP, or general input validation as a fix for another root control.  
- Only fix one route while the same sink/policy is used in other routes.  
- Conclude that a vulnerability exists without saving the source, fixture version, and observable evidence.

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

- **SameSite Cookie**: A cookie attribute that allows developers to control whether the cookie is sent along with requests from other websites, helping to prevent session cookie abuse in CSRF attacks.  
- **Anti-CSRF Token**: A random, secret, and unique string generated by the server for each user session or request, used to verify that the request truly originates from a legitimate application.  
- **Same-Origin Policy**: An important browser security mechanism that prevents scripts on one website from accessing data on another website with a different origin (Domain/Port/Protocol).  
- **Cross-origin request credentials**: Information used to identify the user (such as cookies or authentication headers) that is automatically sent along with network requests to a domain different from the current website’s domain.  
- **Double Submit Cookie**: A defense technique against CSRF by sending an anti-CSRF token both in a cookie and as a request parameter (or header). The server compares the two values, and if they match, the request is accepted.

## 16. Related Lessons and Further Reading

- [Related lessons in the same folder ](../)

## 17. References

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — version/status: current version; accessed: 2026-07-18.
- **[S2]** CWE-352. https://cwe.mitre.org/data/definitions/352.html — version/status: current version; accessed: 2026-07-18.
- **[S3]** OWASP Cross-Site Request Forgery Prevention Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html — version/status: current version; accessed: 2026-07-18.
- **[S4]** csrf-csrf documentation. https://github.com/Psifi-Solutions/csrf-csrf — version/status: 4.x; accessed: 2026-07-18.