---
schema_version: 1
id: WEB-A05-XSS-REFLECTED
title: "Reflected XSS"
slug: xss-reflected
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A05:2025
cwe:
  - CWE-79
content_status: technical-review
payload_status: none
last_verified: null
---

# Reflected XSS

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain Reflected XSS by root cause instead of just describing the consequence.
- Identify trust boundary, asset, actor, and necessary conditions for the vulnerability to be exploited.
- Conduct controlled testing in a local lab and distinguish expected results from false positives.
- Select root controls, implement the fix, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- Understand the flow of HTTP request/response in the Reflected XSS scenario and how to apply input handling across trust boundaries. 
- Distinguish between authentication, authorization, and validation. 
- Be able to read code/configuration in the language or framework appearing in the example. 
- Have an isolated local lab, synthetic data, observable logs, and clear testing permissions.

## 3. Background Knowledge

Imagine the query parameter on URL like a message enclosed in an envelope that you send to the server (for example: `?q=news`). When receiving the envelope, the server will read this message and use it to generate a dynamic response page (such as a search results page for the keyword "news") and then send it back to you. However, if this server is too naive – receiving the message and directly printing it verbatim on the response page without checking whether the message contains dangerous characters of the HTML language – then that is the source of the security vulnerability.

### Example code working normally (Secure Server-Side Rendering)```javascript
const express = require('express');
const app = express();

// Helper function to escape HTML characters and prevent XSS injection
const escapeHtml = (unsafeString) => {
    if (typeof unsafeString !== 'string') {
        return '';
    }
    return unsafeString
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
};

// Express route handling search query parameters
app.get('/search', (req, res) => {
    // Retrieve parameter and ensure it is treated strictly as a string
    const rawQuery = typeof req.query.q === 'string' ? req.query.q : '';

    // Escape user input before interpolating it into server-side HTML rendering
    const safeQuery = escapeHtml(rawQuery);

    // Send response with safely encoded parameters
    res.setHeader('Content-Type', 'text/html');
    res.send(`
        <html>
            <body>
                <h1>Search Results</h1>
                <p>You searched for: <strong>${safeQuery}</strong></p>
            </body>
        </html>
    `);
});
```

## 4. Description and Root Cause

The Reflected XSS (XSS reflection) vulnerability occurs when the server retrieves data from a submitted request and immediately 'reflects' it onto the webpage returned to the browser without passing through a security filter. An attacker can create an URL link containing malicious JavaScript code in the query parameters and then try to trick the victim into clicking it. When the victim clicks the link, the browser sends a request to the server, and the server instantly reflects the malicious code into the returned HTML page. The victim's browser receives the webpage, assumes it is valid system content, and executes the malicious code immediately. The danger of this attack lies in the fact that it happens instantly and can easily allow the attacker to hijack the user's login credentials with just a simple click.

> **Reference:** technical claims in the lesson are marked with source markers; when applying in practice, refer to the version/framework being used: [S1], [S2].

## 5. Threat Model and Exploitation Conditions

- **Assets:** HTML instant response and session visitor.  
- **Actor, authentication, and role:** actor sends link; victim with user role opens public search.  
- **Exploitation conditions:** query input is reflected into HTML without contextual encoding.  
- **Browser, proxy, framework, and version:** Chromium and Express 4.x pinned on .lab.test; must record actual image/package version along with evidence.  
- **Mandatory evidence:** along with correlation ID must append input, determine control, and impact the correct asset; individual status code is not sufficient. [S1]

## 6. Attack Mechanism

For reflected, the query input is reflected into HTML without contextual encoding. The positive case must prove that the input reaches the correct sink and produces the described effect; the negative case, when origin control is enabled, must be blocked before the side effect. The conclusion only applies to the environment pinned in item 5. [S1]

## 7. Testing in an Authorized Lab

1. **Setup:** launch Chromium and Express 4.x pinned on .lab.test; only load synthetic data, enable application/proxy/datastore logs, and attach correlation ID.
2. **Baseline:** send a valid input for the reflected use case; save raw request/response, determine policy and asset status before testing.
3. **Input and actions:** use exactly one core payload from item 8 in the annotated context; change one variable at a time and comply with request cap.
4. **Expected result:** consider the fixture vulnerable as positive only when logs prove the mechanism “query input reflected into HTML without contextual encoding”; the secure fixture must block before side effects and boundary input must fail closed.
5. **Cleanup:** delete data, markers, and logs of reflected; revoke related session/cache, restore snapshot, and confirm no remaining callback/test process.
6. **Safety limits:** run only on loopback/`.lab.test`; do not use target, credentials, or real data; OOB/DoS/state-changing must respect network/CPU/memory/request cap.

## 8. Payloads and Scope of Applicability

The blocks below are minimal lab examples according to the context recorded in the annotation. Before use, check the framework/version, encoding, expected result, and risk; only run in an authorized local fixture. Extended payload belongs to `security_cheatsheet.md`; lessons only retain the core examples.

In the browser lab, `https://victim.lab.test/search?q=banana` reflects the search parameter. A test value that inserts a script only sets `document.body.dataset.labExecuted='true'`; it does not send cookies or data over the network. If the marker appears in the vulnerable fixture but is encoded as text in the secure fixture, the lab has demonstrated the sink XSS in the correct output context.

## 9. Vulnerable Code and Secure Code

The following two handlers use Express 4.x for the same search route. The difference lies in whether untrusted data is inserted directly or properly encoded in the HTML text context before rendering. [S2] [S3] [S4]

### Unsafe (vulnerable): direct input interpolation

```javascript
app.get('/search', (req, res) => {
    const query = typeof req.query.q === 'string' ? req.query.q : '';
    // Vulnerable: user input is interpreted as part of the HTML response
    res.send(`<h1>Search results for: ${query}</h1>`);
});
```
### Secure: encode for HTML text context

```javascript
const escapeHtml = (unsafeString) => {
    if (typeof unsafeString !== 'string') {
        return '';
    }
    return unsafeString
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
};

// Example handler rendering search results
app.get('/search', (req, res) => {
    const query = typeof req.query.q === 'string' ? req.query.q : '';
    const safeQuery = escapeHtml(query);
    // Secure for this HTML text context
    res.send(`<h1>Search results for: ${safeQuery}</h1>`);
});
```

## 10. Detection

- Log the actor/session, route or operation, object/resource related to Reflected XSS, policy result and correlation ID; do not log secrets or full tokens.
- Compare authorization/validation failures with the valid baseline and alert according to behavior chains, not just a single payload chain.
- Combine application telemetry, reverse proxy, and datastore to confirm that the request reached the sink and whether it had any impact.
- Scanner or WAF alert is only an investigation signal; it is not the sole proof that a vulnerability exists. [S1]

## 11. Defense

### Compulsory control

- Render using templates with auto-escaping or properly encode the correct context.
- Apply the same control to all routes, operations, and equivalent processing paths; failure must stop before any side effect.

### Defense-in-depth

With Reflected XSS, the measures below help reduce the blast radius or increase detection capability. Rate limit, UUID hard to predict, WAF, CSP, or general validation should not be used as a substitute for original controls.

- **Summary**: Prevent Reflected XSS by encoding output data according to the display context, strictly validating input data types, and implementing a Content Security Policy (CSP).
- **Detailed steps**:
  - Perform context-aware output encoding (HTML body, HTML attributes, JavaScript scripts, or URL parameters) for all user-supplied data before returning it.
  - Validate and sanitize all input parameters using an allowlist mechanism.
  - Implement a strict Content Security Policy (CSP) to prohibit execution of untrusted inline scripts and restrict allowed script sources.
  - Use modern frameworks (React, Angular, Vue) that provide integrated safe output encoding by default.
  - Set response headers `X-Content-Type-Options: nosniff` to prevent MIME-sniffing attacks.

## 12. Retest

- **Positive case:** with Reflected XSS, the valid flow still works correctly for the actor and allowed data.  
- **Negative case:** with the same input/resource but the actor or context is not allowed, it should be rejected without leaking sensitive details.  
- **Boundary case:** check empty values, extreme edges, different encodings, repeated requests, expired session states, and equivalent paths/operations.  
- **Telemetry:** confirm that policy decisions, application logs, proxy logs, and datastore side effects match correlation ID.  
- **Recheck:** save a minimal scenario reproducing the old error and demonstrate the fix does not depend on WAF/rate limit.

## 13. Common Mistakes

- Only check the status code or response string of Reflected XSS without verifying side effects and logs.  
- Use a payload with the correct syntax but wrong DBMS, browser, framework, protocol, or injection context.  
- Treat UUID, rate limit, WAF, CSP, or general input validation as fixed by another root control.  
- Only fix one route while the same sink/policy is used in another route.  
- Conclude that a vulnerability exists without recording the source, fixture version, and observable evidence.

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

- **Reflected XSS**: The XSS reflected vulnerability, malware is sent via request and immediately returned in the server's response.
- **Query Parameter**: The parameter attached in the URL path to transmit data.
- **Server-Side Rendering**: The method of rendering the entire HTML interface dynamically on the server before sending it to the client.
- **Payload**: The exploit code inserted into the system by the attacker.
- **HTML Entity**: A special encoded character representing HTML tags to prevent the browser from misinterpreting them as executable commands.

## 16. Related Lessons and Further Reading

- [Stored XSS](../stored/) — Stored XSS vulnerability.

## 17. References

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — version/status: current version; accessed: 2026-07-17.
- **[S2]** CWE-79. https://cwe.mitre.org/data/definitions/79.html — version/status: current version; accessed: 2026-07-17.
- **[S3]** OWASP Cross Site Scripting Prevention Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html — version/status: current version; accessed: 2026-07-18.
- **[S4]** OWASP WSTG — Testing for Reflected Cross Site Scripting. https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting — version/status: latest; accessed: 2026-07-18.